"""Phase 2.0-A.3.12 Evidence-Grounded Diagnostic Reasoning Tests.

Verifies:
1. Goal text keyword immunity: Rephrasing or removing keywords from the goal prompt
   does not change diagnostic verdict if underlying evidence is unchanged.
2. Evidence-based confidence scoring: No fixed constants (0.85/0.15); confidence is derived
   deterministically from evidence quality and record counts.
3. Competing hypothesis evaluation: Directly discriminates competing hypotheses across
   SUPPORTED, REFUTED, INCONCLUSIVE, and NOT_TESTED.
4. Honest causal verification: Distinguishes static correlational observation (SUSPECTED)
   from verified causal proof/transition (CONFIRMED).
5. Honest inconclusive / abstention: When evidence is insufficient, contradictory, or
   budget exhausted, returns INCONCLUSIVE or ABSTAINED.
"""

import os
import unittest
from unittest.mock import patch

from extractor.workflow import (
    DIAG_CONFIRMED,
    DIAG_INCONCLUSIVE,
    DIAG_NO_ISSUE_DETECTED_WITHIN_SCOPE,
    DIAG_SUSPECTED,
    HYPOTHESIS_STATUS_INCONCLUSIVE,
    HYPOTHESIS_STATUS_NOT_TESTED,
    HYPOTHESIS_STATUS_REFUTED,
    HYPOTHESIS_STATUS_SUPPORTED,
    STAGE_FORMING_DIAGNOSIS,
    InvestigationWorkflowDefinition,
    InvestigationWorkflowEngine,
    WorkflowExecutionState,
)
from extractor.evidence_ledger import (
    EVIDENCE_TYPE_FIELD_OBSERVATION,
    EvidenceLedger,
    EvidenceRecord,
    PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
)
from extractor.capture_backend import (
    issue_causal_attestation,
    get_trusted_causal_authority_token,
)
from extractor.target_adapter import LocalTargetAdapter


class TestPhase20A312DiagnosticReasoning(unittest.TestCase):
    def setUp(self):
        self.engine = InvestigationWorkflowEngine()
        self.pid = 4321

    def _setup_mock_adapter(self, threads=None):
        adapter = LocalTargetAdapter()
        threads_list = threads if threads is not None else [
            {"tid": 4321, "state": "R", "is_running_user_space": True, "voluntary_ctxt_switches": 10, "wchan": "0"},
            {"tid": 4322, "state": "R", "is_running_user_space": True, "voluntary_ctxt_switches": 12, "wchan": "0"},
        ]
        adapter.check_liveness = lambda p: (True, None)
        adapter.get_threads = lambda p: threads_list
        adapter.get_proc_maps = lambda p: [{"start_int": 0x400000, "end_int": 0x410000, "size": 65536, "is_readable": True, "category": "heap"}]
        adapter.get_process_identity = lambda p: {
            "pid": p,
            "process_identity": f"{p}:1000:boot",
            "start_time": "1000",
            "executable": "/usr/bin/target",
            "executable_identity": "/usr/bin/target:123",
            "build_id": "deadbeef",
        }
        def _mock_read(p, a, s):
            data = b"\x00" * s
            adapter._record_physical_read(len(data), 1, data=data, pid=p, address=a, requested_size=s, status="OBSERVED")
            return data, "OBSERVED", None
        adapter.read_memory = _mock_read
        return adapter

    # -------------------------------------------------------------------------
    # 1. Goal Text Keyword Immunity
    # -------------------------------------------------------------------------
    def test_01_goal_keyword_does_not_alter_diagnosis(self):
        """Prompt keyword 'deadlock' must not trick the engine into declaring deadlock on a healthy process."""
        adapter = self._setup_mock_adapter()
        engine = InvestigationWorkflowEngine(target_adapter=adapter)

        # Instance 1: Goal explicitly mentions "investigate severe deadlock condition"
        inst_deadlock_prompt = engine.create_instance(
            session_id="sess_kw_1",
            target_pid=self.pid,
            goal="Please investigate severe deadlock condition on worker threads",
        )
        res1 = engine.execute_investigation(inst_deadlock_prompt)

        # Instance 2: Goal mentions "routine memory check"
        inst_benign_prompt = engine.create_instance(
            session_id="sess_kw_2",
            target_pid=self.pid,
            goal="Routine memory and performance check",
        )
        res2 = engine.execute_investigation(inst_benign_prompt)

        # Both must produce identical verdict based on actual evidence, ignoring the keyword
        self.assertEqual(res1["context"]["diagnosis"], DIAG_NO_ISSUE_DETECTED_WITHIN_SCOPE)
        self.assertEqual(res2["context"]["diagnosis"], DIAG_NO_ISSUE_DETECTED_WITHIN_SCOPE)
        self.assertEqual(res1["context"]["diagnosis"], res2["context"]["diagnosis"])

    # -------------------------------------------------------------------------
    # 2. Evidence-Based Confidence Scoring
    # -------------------------------------------------------------------------
    def test_02_confidence_derived_from_evidence_not_fixed_constants(self):
        """Hypothesis confidence must be derived from evidence quantity and quality, not fixed constants (0.85/0.15)."""
        adapter = self._setup_mock_adapter()
        engine = InvestigationWorkflowEngine(target_adapter=adapter)

        inst = engine.create_instance(session_id="sess_conf_1", target_pid=self.pid, goal="Confidence test")
        engine.execute_stage_initializing(inst)
        engine.execute_stage_probing(inst)
        engine.execute_stage_formulating_hypothesis(inst)
        engine.execute_stage_selecting_recipe(inst)
        engine.execute_stage_executing_observation(inst)
        engine.execute_stage_evaluating_evidence(inst)
        engine.execute_stage_updating_hypothesis(inst)

        hyps = {h["id"]: h for h in inst.context["hypotheses"]}
        norm_conf = hyps["hyp_normal"]["confidence"]
        dead_conf = hyps["hyp_deadlock"]["confidence"]

        # Confidence scores must not be equal to the old hardcoded 0.85 / 0.15
        self.assertNotEqual(norm_conf, 0.85)
        self.assertNotEqual(dead_conf, 0.15)
        # Healthy hypothesis supported by observation should have calibrated score
        self.assertGreater(norm_conf, hyps["hyp_normal"]["prior"])
        self.assertEqual(hyps["hyp_deadlock"]["status"], HYPOTHESIS_STATUS_REFUTED)

    # -------------------------------------------------------------------------
    # 3. Competing Hypotheses Discrimination
    # -------------------------------------------------------------------------
    def test_03_competing_hypotheses_evaluation_and_discrimination(self):
        """Contention signals promote deadlock hypothesis and refute normal operation hypothesis."""
        contended_threads = [
            {"tid": 4321, "state": "S", "wchan": "futex_wait_queue", "voluntary_ctxt_switches": 100},
            {"tid": 4322, "state": "S", "wchan": "futex_wait_queue", "voluntary_ctxt_switches": 150},
        ]
        adapter = self._setup_mock_adapter(threads=contended_threads)
        engine = InvestigationWorkflowEngine(target_adapter=adapter)

        inst = engine.create_instance(session_id="sess_comp_1", target_pid=self.pid, goal="Contention test")
        engine.execute_stage_initializing(inst)
        engine.execute_stage_probing(inst)
        engine.execute_stage_formulating_hypothesis(inst)
        engine.execute_stage_selecting_recipe(inst)
        engine.execute_stage_executing_observation(inst)
        engine.execute_stage_evaluating_evidence(inst)
        engine.execute_stage_updating_hypothesis(inst)
        engine.execute_stage_checking_budget(inst)
        engine.execute_stage_comparing_competing(inst)

        hyps = {h["id"]: h for h in inst.context["hypotheses"]}
        self.assertEqual(hyps["hyp_deadlock"]["status"], HYPOTHESIS_STATUS_SUPPORTED)
        self.assertEqual(hyps["hyp_normal"]["status"], HYPOTHESIS_STATUS_REFUTED)
        self.assertEqual(inst.context["primary_hypothesis"]["id"], "hyp_deadlock")

    # -------------------------------------------------------------------------
    # 4. Honest Causal Verification (SUSPECTED vs CONFIRMED)
    # -------------------------------------------------------------------------
    def test_04_static_observation_yields_suspected_while_causal_proof_yields_confirmed(self):
        """Static observation yields SUSPECTED diagnosis; verified causal proof yields CONFIRMED."""
        contended_threads = [
            {"tid": 4321, "state": "S", "wchan": "futex_wait_queue", "voluntary_ctxt_switches": 100},
            {"tid": 4322, "state": "S", "wchan": "futex_wait_queue", "voluntary_ctxt_switches": 150},
        ]
        adapter = self._setup_mock_adapter(threads=contended_threads)
        engine = InvestigationWorkflowEngine(target_adapter=adapter)

        # 4.1: Static observation without causal proof
        inst_static = engine.create_instance(session_id="sess_static", target_pid=self.pid, goal="Static check")
        res_static = engine.execute_investigation(inst_static)
        self.assertEqual(res_static["context"]["diagnosis"], DIAG_SUSPECTED)
        self.assertFalse(res_static["context"]["causation_verified"])

        # 4.2: Add authentic causal proof to ledger -> yields CONFIRMED
        engine2 = InvestigationWorkflowEngine(target_adapter=adapter)
        inst_causal = engine2.create_instance(session_id="sess_causal", target_pid=self.pid, goal="Causal check")
        engine2.execute_stage_initializing(inst_causal)
        engine2.execute_stage_probing(inst_causal)
        engine2.execute_stage_formulating_hypothesis(inst_causal)
        engine2.execute_stage_selecting_recipe(inst_causal)
        engine2.execute_stage_executing_observation(inst_causal)
        engine2.execute_stage_evaluating_evidence(inst_causal)

        with adapter.capture_transaction("sess_causal", self.pid, operation_type="diagnostic") as tx2:
            adapter.read_memory(self.pid, 0x400000, 64)
        rcpt2 = adapter.issue_live_receipt_for_session("sess_causal", self.pid, transaction=tx2)

        existing_records = engine2.evidence_ledger._records
        pre_id = existing_records[0].evidence_id if existing_records else ""

        causal_att = issue_causal_attestation(
            session_id="sess_causal",
            target_identity=inst_causal.context.get("pinned_identity"),
            operation_id="op_causal_1",
            precondition_evidence_id=pre_id,
            postcondition_evidence_id="ev_causal_trans_1",
            claimed_transition={"lock_state": "transitioned"},
            authority_level="PRODUCTION",
            verifier_authority_token=get_trusted_causal_authority_token(),
        )

        # Inject verified deterministic transition record into ledger
        causal_rec = EvidenceRecord(
            evidence_id="ev_causal_trans_1",
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            observation="Verified deterministic transition of lock state",
            provenance={
                "provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
                "live_capture_receipt": rcpt2.to_dict(),
                "causal_attestation": causal_att.to_dict(),
            },
            details={"causal_proof": True, "deterministic_transition_verified": True},
            target_identity=inst_causal.context.get("pinned_identity"),
            session_id="sess_causal",
        )
        engine2.evidence_ledger.add_record(causal_rec)

        engine2.execute_stage_updating_hypothesis(inst_causal)
        engine2.execute_stage_checking_budget(inst_causal)
        engine2.execute_stage_comparing_competing(inst_causal)
        engine2.execute_stage_verifying_causation(inst_causal)
        engine2.execute_stage_forming_diagnosis(inst_causal)

        self.assertTrue(inst_causal.context["causation_verified"])
        self.assertEqual(inst_causal.context["diagnosis"], DIAG_CONFIRMED)

    # -------------------------------------------------------------------------
    # 5. Honest Inconclusive and Abstention
    # -------------------------------------------------------------------------
    def test_05_insufficient_evidence_or_budget_exhaustion_yields_inconclusive_or_abstain(self):
        """When evidence is insufficient or budget is exhausted, honest INCONCLUSIVE or ABSTAINED is returned."""
        adapter = self._setup_mock_adapter()
        engine = InvestigationWorkflowEngine(target_adapter=adapter)

        # Insufficient evidence
        inst_inconclusive = engine.create_instance(session_id="sess_inc", target_pid=self.pid, goal="Ambiguous")
        inst_inconclusive.context["evidence_sufficient"] = False
        inst_inconclusive.context["primary_hypothesis"] = {"id": "hyp_unknown", "status": HYPOTHESIS_STATUS_INCONCLUSIVE}
        engine.execute_stage_forming_diagnosis(inst_inconclusive)
        self.assertEqual(inst_inconclusive.context["diagnosis"], DIAG_INCONCLUSIVE)

        # Budget exhausted
        inst_budget = engine.create_instance(session_id="sess_bud", target_pid=self.pid, goal="Exhausted")
        inst_budget.context["budget_exhausted"] = True
        inst_budget.context["budget_exhausted_reason"] = "Physical byte budget exceeded limit"
        engine.execute_stage_checking_budget(inst_budget)
        self.assertEqual(inst_budget.current_stage, "ABSTAINED")
        self.assertEqual(inst_budget.status, "ABSTAINED")


if __name__ == "__main__":
    unittest.main()
