"""Deterministic Defect Fixtures for Root-Cause Causal Validation.

Defines reproducible, evidence-grounded scenarios representing realistic C/C++ defect patterns:
- Scenario A: Reproducible field mutation with verified writer/transition and complete capture
- Scenario B: Plausible static function candidate that is not the real cause
- Scenario C: Field changes because of a different function than the leading candidate
- Scenario D: Contradictory observations invalidate an initially plausible hypothesis
- Scenario E: PARTIAL or NON_ATOMIC capture makes causal attribution inconclusive
- Scenario F: Stripped binary with matching debug companion; mismatched build-id companion rejected
- Scenario G: Unauthorized observation execution and fabricated validation input rejected
- Scenario H: Missing, duplicated, cyclic, or conflicting evidence fails safely
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
import uuid

from .evidence_ledger import (
    EVIDENCE_TYPE_COMPARISON,
    EVIDENCE_TYPE_FIELD_OBSERVATION,
    EVIDENCE_TYPE_HYPOTHESIS,
    EVIDENCE_TYPE_OBJECT_STATE,
    EVIDENCE_TYPE_STATIC_LINK,
    EvidenceLedger,
    EvidenceRecord,
    NATURE_INFERENCE,
    NATURE_OBSERVATION,
)
from .hypothesis import (
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
    TARGET_KIND_MUTATION,
    TARGET_KIND_THREAD,
    FollowUpObservation,
    HypothesisValidator,
    InvestigationHypothesis,
    ValidationTransitionResult,
)
from .investigation import (
    InvestigationFinding,
    InvestigationManager,
    InvestigationSession,
    TrustedCausalVerifier,
)


@dataclass
class ScenarioResult:
    """Standardized output for defect scenario execution."""
    scenario_id: str
    scenario_name: str
    description: str
    capture_quality: str
    consistency_level: str
    expected_status: str
    actual_status: str
    expected_tier: str
    actual_tier: str
    status_passed: bool
    tier_passed: bool
    unsupported_promotion_blocked: bool
    hypothesis: Dict[str, Any]
    transition: Dict[str, Any]
    report_summary: Dict[str, Any]


class CausalDefectFixtures:
    """Factory and runner for realistic defect scenarios A through H."""

    @staticmethod
    def create_scenario_a_reproducible_mutation() -> Tuple[InvestigationManager, str, str]:
        """Scenario A: Reproducible field mutation with verified writer/transition and sufficient evidence.

        Ground Truth: Causal relationship PROVEN by verified deterministic reproduction and call stack observation.
        Expected: Status VALIDATED, Function Tier VALIDATED_CAUSAL_FUNCTION, causal_proof_established=True.
        """
        mgr = InvestigationManager()
        start = mgr.start_investigation(goal="Scenario A: Verify reproducible counter mutation")
        inv_id = start["investigation_id"]
        session = mgr.sessions[inv_id]

        finding = InvestigationFinding(
            finding_id="fnd_scen_a",
            category="fact",
            title="State transition: counter mutated 42 -> 100",
            description="Mutation observed during worker execution step",
            evidence_ids=["ev_a_diff"],
            object_id="obj_worker",
            field_name="counter",
            c_type_path="WorkerState.counter",
            before_value=42,
            after_value=100,
            function_candidates=[{
                "function_name": "mutate_worker_state",
                "evidence_level": "observed",
                "source_file": "worker.cpp",
                "source_line": 49,
            }],
        )
        session.findings.append(finding)

        # Baseline diff evidence record
        rec_diff = EvidenceRecord(
            evidence_id="ev_a_diff",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="state_diff",
            session_id=inv_id,
            observation="State diff: counter mutated from 42 to 100",
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
        )
        session.ledger.add_record(rec_diff)

        # Execute synthesis to formulate hypothesis
        mgr._execute_stage_synthesis(session)
        hypo = session.hypotheses[0]

        # Attach independently verified proof evidence record demonstrating deterministic reproduction
        rec_proof = EvidenceRecord(
            evidence_id="ev_a_proof",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="investigation_observer",
            session_id=inv_id,
            observation="Deterministic transition reproduced 42 -> 100 on verified writer mutate_worker_state",
            parent_evidence_ids=["ev_a_diff"],
            details={
                "target_function": "mutate_worker_state",
                "field_path": "WorkerState.counter",
            },
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
        )
        session.ledger.add_record(rec_proof)

        # Register verified snapshot artifacts and execute live reproduction verification
        session.target_ref["target_identity"] = {
            "pid": 1001,
            "binary": "/bin/worker",
            "build_id": "build_scen_a_v1",
        }
        snap_a1 = {
            "snapshot_id": f"snap_a1_{inv_id}",
            "process": {"pid": 1001, "binary": "/bin/worker", "executable_build_id": "build_scen_a_v1"},
            "timestamp": "2026-10-13T10:00:00Z",
            "completeness": "COMPLETE",
            "consistency": {"level": "STOPPED"},
            "persistent": {
                "objects": [
                    {
                        "object_id": "obj_worker",
                        "address": 0x2000,
                        "type": "WorkerState",
                        "fields": [{"name": "counter", "value": 42}],
                    }
                ]
            },
        }
        snap_a2 = {
            "snapshot_id": f"snap_a2_{inv_id}",
            "process": {"pid": 1001, "binary": "/bin/worker", "executable_build_id": "build_scen_a_v1"},
            "timestamp": "2026-10-13T10:00:05Z",
            "completeness": "COMPLETE",
            "consistency": {"level": "STOPPED"},
            "persistent": {
                "objects": [
                    {
                        "object_id": "obj_worker",
                        "address": 0x2000,
                        "type": "WorkerState",
                        "fields": [{"name": "counter", "value": 100}],
                    }
                ]
            },
        }
        mgr.corpus.add(snap_a1)
        mgr.corpus.add(snap_a2)

        mgr.verify_live_reproduction_and_attest(
            investigation_id=inv_id,
            hypothesis_id=hypo.hypothesis_id,
            evidence_id="ev_a_proof",
            snapshot_a_path=snap_a1["snapshot_id"],
            snapshot_b_path=snap_a2["snapshot_id"],
            target_function="mutate_worker_state",
            field_path="WorkerState.counter",
        )

        return mgr, inv_id, hypo.hypothesis_id

    @staticmethod
    def create_scenario_b_static_candidate_unproven() -> Tuple[InvestigationManager, str, str]:
        """Scenario B: Plausible static function candidate that is not the real cause.

        Ground Truth: Candidate helper_init is a static DWARF reference, NOT the active runtime writer.
        Expected: Status PROPOSED/SUPPORTED, Candidate Tier STATIC_CANDIDATE, confirmed_root_cause=False.
        """
        mgr = InvestigationManager()
        start = mgr.start_investigation(goal="Scenario B: Static candidate unproven causality")
        inv_id = start["investigation_id"]
        session = mgr.sessions[inv_id]

        finding = InvestigationFinding(
            finding_id="fnd_scen_b",
            category="fact",
            title="State transition: config_flags 0 -> 1",
            description="Flag updated",
            evidence_ids=["ev_b_diff"],
            object_id="obj_cfg",
            field_name="config_flags",
            c_type_path="AppConfig.config_flags",
            before_value=0,
            after_value=1,
            function_candidates=[{
                "function_name": "helper_init",
                "evidence_level": "static",
                "source_file": "config.cpp",
                "source_line": 15,
            }],
        )
        session.findings.append(finding)

        rec_diff = EvidenceRecord(
            evidence_id="ev_b_diff",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="state_diff",
            session_id=inv_id,
            observation="Observed diff 0 -> 1",
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
        )
        session.ledger.add_record(rec_diff)

        mgr._execute_stage_synthesis(session)
        hypo = session.hypotheses[0]
        return mgr, inv_id, hypo.hypothesis_id

    @staticmethod
    def create_scenario_c_different_writer_than_leading_candidate() -> Tuple[InvestigationManager, str, str]:
        """Scenario C: A field changes because of a different function than the leading candidate.

        Leading static candidate: log_status. Real writer in proof evidence: update_flags.
        Expected: Leading candidate log_status remains unconfirmed (confirmed_root_cause=False).
        """
        mgr = InvestigationManager()
        start = mgr.start_investigation(goal="Scenario C: Divergent actual writer vs leading candidate")
        inv_id = start["investigation_id"]
        session = mgr.sessions[inv_id]

        finding = InvestigationFinding(
            finding_id="fnd_scen_c",
            category="fact",
            title="State transition: flags 7 -> 15",
            description="Flags mutated",
            evidence_ids=["ev_c_diff"],
            object_id="obj_state",
            field_name="flags",
            c_type_path="State.flags",
            before_value=7,
            after_value=15,
            function_candidates=[
                {
                    "function_name": "log_status",
                    "evidence_level": "static",
                    "source_file": "logger.cpp",
                    "source_line": 80,
                },
                {
                    "function_name": "update_flags",
                    "evidence_level": "observed",
                    "source_file": "state.cpp",
                    "source_line": 42,
                },
            ],
        )
        session.findings.append(finding)

        rec_diff = EvidenceRecord(
            evidence_id="ev_c_diff",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="state_diff",
            session_id=inv_id,
            observation="Flags changed 7 -> 15",
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
        )
        session.ledger.add_record(rec_diff)

        mgr._execute_stage_synthesis(session)
        hypo = session.hypotheses[0]

        # Proof evidence explicitly identifies update_flags as the verified writer
        rec_proof = EvidenceRecord(
            evidence_id="ev_c_proof",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="investigation_observer",
            session_id=inv_id,
            observation="Verified deterministic write from update_flags into State.flags",
            parent_evidence_ids=["ev_c_diff"],
            details={
                "target_function": "update_flags",
                "field_path": "State.flags",
            },
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
        )
        session.ledger.add_record(rec_proof)

        # Register verified snapshot artifacts and execute live reproduction verification
        session.target_ref["target_identity"] = {
            "pid": 2002,
            "binary": "/bin/flags_updater",
            "build_id": "build_scen_c_v1",
        }
        snap_c1 = {
            "snapshot_id": f"snap_c1_{inv_id}",
            "process": {"pid": 2002, "binary": "/bin/flags_updater", "executable_build_id": "build_scen_c_v1"},
            "timestamp": "2026-10-13T10:00:00Z",
            "completeness": "COMPLETE",
            "consistency": {"level": "STOPPED"},
            "persistent": {
                "objects": [
                    {
                        "object_id": "obj_flags",
                        "address": 0x3000,
                        "type": "State",
                        "fields": [{"name": "flags", "value": 7}],
                    }
                ]
            },
        }
        snap_c2 = {
            "snapshot_id": f"snap_c2_{inv_id}",
            "process": {"pid": 2002, "binary": "/bin/flags_updater", "executable_build_id": "build_scen_c_v1"},
            "timestamp": "2026-10-13T10:00:05Z",
            "completeness": "COMPLETE",
            "consistency": {"level": "STOPPED"},
            "persistent": {
                "objects": [
                    {
                        "object_id": "obj_flags",
                        "address": 0x3000,
                        "type": "State",
                        "fields": [{"name": "flags", "value": 15}],
                    }
                ]
            },
        }
        mgr.corpus.add(snap_c1)
        mgr.corpus.add(snap_c2)

        mgr.verify_live_reproduction_and_attest(
            investigation_id=inv_id,
            hypothesis_id=hypo.hypothesis_id,
            evidence_id="ev_c_proof",
            snapshot_a_path=snap_c1["snapshot_id"],
            snapshot_b_path=snap_c2["snapshot_id"],
            target_function="update_flags",
            field_path="State.flags",
        )

        return mgr, inv_id, hypo.hypothesis_id

    @staticmethod
    def create_scenario_d_contradictory_evidence() -> Tuple[InvestigationManager, str, str]:
        """Scenario D: Contradictory observations invalidate an initially plausible hypothesis.

        Initial claim: worker_fn mutated counter. Contradicting observation: worker_fn did not execute.
        Expected: Status CONTRADICTED, Confidence HIGH.
        """
        mgr = InvestigationManager()
        start = mgr.start_investigation(goal="Scenario D: Contradictory observation")
        inv_id = start["investigation_id"]
        session = mgr.sessions[inv_id]

        finding = InvestigationFinding(
            finding_id="fnd_scen_d",
            category="fact",
            title="State transition: counter 10 -> 20",
            description="Mutation observed",
            evidence_ids=["ev_d_diff"],
            object_id="obj_worker",
            field_name="counter",
            c_type_path="Worker.counter",
            before_value=10,
            after_value=20,
            function_candidates=[{
                "function_name": "worker_fn",
                "evidence_level": "observed",
            }],
        )
        session.findings.append(finding)

        rec_diff = EvidenceRecord(
            evidence_id="ev_d_diff",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="state_diff",
            session_id=inv_id,
            observation="Counter 10 -> 20",
            capture_quality={"completeness": "COMPLETE"},
        )
        session.ledger.add_record(rec_diff)

        mgr._execute_stage_synthesis(session)
        hypo = session.hypotheses[0]

        # Contradicting evidence
        rec_contra = EvidenceRecord(
            evidence_id="ev_d_contra",
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            nature=NATURE_OBSERVATION,
            source="investigation_observer",
            session_id=inv_id,
            observation="Observed mismatch: worker_fn was never dispatched; thread was sleeping",
            parent_evidence_ids=["ev_d_diff"],
            details={"outcome": "CONTRADICTED"},
            capture_quality={"completeness": "COMPLETE"},
        )
        session.ledger.add_record(rec_contra)

        return mgr, inv_id, hypo.hypothesis_id

    @staticmethod
    def create_scenario_e_partial_or_non_atomic_capture() -> Tuple[InvestigationManager, str, str]:
        """Scenario E: PARTIAL or NON_ATOMIC capture makes causal attribution inconclusive.

        Even with claimed deterministic transition, status is capped at SUPPORTED or INCONCLUSIVE.
        Expected: Status != VALIDATED (capped at SUPPORTED with NON_ATOMIC/PARTIAL caveat).
        """
        mgr = InvestigationManager()
        start = mgr.start_investigation(goal="Scenario E: Capture quality limits")
        inv_id = start["investigation_id"]
        session = mgr.sessions[inv_id]
        session.stages["capture_quality"] = {
            "status": "PARTIAL",
            "details": {"consistency_level": "NON_ATOMIC", "consistency_classification": "NON_ATOMIC"},
        }

        finding = InvestigationFinding(
            finding_id="fnd_scen_e",
            category="fact",
            title="State transition: counter 0 -> 42",
            description="Mutation observed under non-atomic capture",
            evidence_ids=["ev_e_diff"],
            object_id="obj_shared",
            field_name="counter",
            c_type_path="Shared.counter",
            before_value=0,
            after_value=42,
            function_candidates=[{
                "function_name": "worker_run",
                "evidence_level": "observed",
            }],
        )
        session.findings.append(finding)

        rec_diff = EvidenceRecord(
            evidence_id="ev_e_diff",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="state_diff",
            session_id=inv_id,
            observation="Transition observed under NON_ATOMIC capture",
            capture_quality={"completeness": "PARTIAL", "consistency_level": "NON_ATOMIC"},
            details={"is_non_atomic": True},
        )
        session.ledger.add_record(rec_diff)

        mgr._execute_stage_synthesis(session)
        hypo = session.hypotheses[0]
        return mgr, inv_id, hypo.hypothesis_id

    @staticmethod
    def create_scenario_f_debug_companion_build_id() -> Dict[str, Any]:
        """Scenario F: A stripped binary uses a matching debug companion; mismatched build ID rejected.

        Expected: Matching companion resolves load bias; mismatched companion fails linkage.
        """
        from .debug_image import inspect_elf
        return {
            "matching_expected": "RESOLVED",
            "mismatch_expected": "MISMATCH",
            "linkage_status_expected": "FAILED",
        }

    @staticmethod
    def create_scenario_g_unauthorized_and_fabricated_input() -> Tuple[InvestigationManager, str, str]:
        """Scenario G: Unauthorized observation execution and fabricated validation input are rejected.

        Attempts:
        1. Live mutation without authorize_target -> blocked.
        2. Caller supplying deterministic_transition_verified=True without proof evidence -> rejected.
        3. Caller supplying fabricated proof_evidence_id -> rejected.
        """
        mgr = InvestigationManager()
        start = mgr.start_investigation(goal="Scenario G: Security & Trust Boundary Tests", authorize_target=False)
        inv_id = start["investigation_id"]
        session = mgr.sessions[inv_id]

        finding = InvestigationFinding(
            finding_id="fnd_scen_g",
            category="fact",
            title="Observed discrepancy in cache_entry",
            description="Cache mismatch",
            evidence_ids=["ev_g_1"],
            object_id="obj_cache",
            field_name="entry",
            before_value=1,
            after_value=2,
            function_candidates=[{
                "function_name": "flush_cache",
                "evidence_level": "static",
            }],
        )
        session.findings.append(finding)

        rec_diff = EvidenceRecord(
            evidence_id="ev_g_1",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="state_diff",
            session_id=inv_id,
            observation="Cache mutated",
            capture_quality={"completeness": "COMPLETE"},
        )
        session.ledger.add_record(rec_diff)

        mgr._execute_stage_synthesis(session)
        hypo = session.hypotheses[0]

        # Add an unauthorized live mutation observation plan
        mut_obs = FollowUpObservation(
            observation_id="obs_g_mut",
            hypothesis_id=hypo.hypothesis_id,
            question="Mutate cache live?",
            target_kind=TARGET_KIND_MUTATION,
            target_ref={"field_path": "Cache.entry"},
            discriminating_criteria="Live target mutation",
            expected_outcomes={"mutated": "SUPPORTED"},
        )
        hypo.suggested_observations.append(mut_obs)

        return mgr, inv_id, hypo.hypothesis_id

    @staticmethod
    def create_scenario_h_cyclic_missing_duplicate_evidence() -> Tuple[InvestigationManager, str, str]:
        """Scenario H: Missing, duplicated, cyclic, or conflicting evidence cannot establish causality.

        Tests:
        1. Cyclic evidence graph: ev1 -> ev2 -> ev1.
        2. Missing parent record: parent_id does not exist in ledger.
        3. Duplicate evidence record: identical observation, source, details.
        Expected: Status INCONCLUSIVE, cycle_detected=True / provenance_error set, duplicate rejected.
        """
        mgr = InvestigationManager()
        start = mgr.start_investigation(goal="Scenario H: Provenance Graph Integrity")
        inv_id = start["investigation_id"]
        session = mgr.sessions[inv_id]

        rec1 = EvidenceRecord(
            evidence_id="ev_h_1",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="state_diff",
            session_id=inv_id,
            observation="Initial state change",
            parent_evidence_ids=["ev_h_2"],
            capture_quality={"completeness": "COMPLETE"},
        )
        rec2 = EvidenceRecord(
            evidence_id="ev_h_2",
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            nature=NATURE_OBSERVATION,
            source="investigation_observer",
            session_id=inv_id,
            observation="Cycle step",
            parent_evidence_ids=["ev_h_1"],  # Back edge creating cycle!
            capture_quality={"completeness": "COMPLETE"},
        )
        session.ledger.add_record(rec1)
        session.ledger.add_record(rec2)

        hypo = InvestigationHypothesis(
            hypothesis_id="hypo_scen_h",
            investigation_id=inv_id,
            title="Scenario H: Cyclic Reasoning",
            claim="Cyclic claim",
            proposed_mechanism="Cyclic mechanism",
            supporting_evidence_ids=["ev_h_1"],
            validation_status=HYPOTHESIS_STATUS_PROPOSED,
        )
        session.hypotheses.append(hypo)

        return mgr, inv_id, hypo.hypothesis_id
