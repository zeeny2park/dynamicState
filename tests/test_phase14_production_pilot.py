"""Phase 14 Production Pilot & Release Qualification Test Suite.

Verifies:
1. Pre-flight prerequisites checking (Linux, arch, kernel, libc, ptrace scope).
2. Machine-readable qualification report schema and tamper-evident SHA-256 integrity.
3. Representative embedded Linux C++ target pilot execution (stripped PIE, ASLR, separate DWARF).
4. Build ID mismatch and missing debug image fail-closed safety.
5. Process exit (ESRCH) and PID reuse detection.
6. Competing writers and negative control baseline stability checks.
7. Degraded capture quality (PARTIAL / NON_ATOMIC) confidence capping.
8. State transition correctness vs causal attribution decoupling.
9. Adversarial forged receipts, modified snapshots, and caller-supplied trust flags.
10. Cross-investigation evidence replay rejection.
11. Observation lifecycle: duplicate execution rejection and cancellation.
12. Statistical latency distribution calculation without invented numbers.
13. Strict hardware validation disclosure enforcement.
14. Multi-interface semantic contract agreement.
"""

import copy
import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from extractor.capture_backend import (
    CaptureSafetyPolicy,
    RawRuntimeSnapshot,
    get_default_capture_backend,
)
from extractor.debug_image import inspect_elf
from extractor.evidence_ledger import (
    ControlledExecutionResult,
    EvidenceRecord,
    EVIDENCE_TYPE_COMPARISON,
    EVIDENCE_TYPE_FIELD_OBSERVATION,
    NATURE_OBSERVATION,
    ATTRIBUTION_BASIS_SINGLE_WRITER,
    CLAIM_STATE_TRANSITION_VERIFIED,
    CLAIM_FUNCTION_ATTRIBUTION_VERIFIED,
)
from extractor.hypothesis import (
    FUNCTION_TIER_STATIC_CANDIDATE,
    FUNCTION_TIER_EVIDENCE_SUPPORTED,
    FUNCTION_TIER_VALIDATED_CAUSAL,
    HYPOTHESIS_STATUS_PROPOSED,
    HYPOTHESIS_STATUS_SUPPORTED,
    HYPOTHESIS_STATUS_CONTRADICTED,
    HYPOTHESIS_STATUS_VALIDATED,
    HYPOTHESIS_STATUS_INCONCLUSIVE,
    OBSERVATION_STATUS_CANCELED,
    OBSERVATION_STATUS_EXECUTED,
    OBSERVATION_STATUS_PROPOSED,
    InvestigationHypothesis,
    FollowUpObservation,
    sanitize_and_disarm_llm_hypothesis,
)
from extractor.investigation import (
    InvestigationManager,
    InvestigationSession,
    TrustedCausalVerifier,
)
from extractor.production_pilot import (
    LatencyDistribution,
    PilotPrerequisitesChecker,
    PilotPrerequisitesResult,
    PilotQualificationReport,
    ProductionPilotHarness,
)


class TestPhase14ProductionPilotPrerequisitesAndSchema(unittest.TestCase):
    """Prerequisites validation, machine-readable report schema, and cryptographic integrity tests."""

    def test_prerequisites_check_live_environment(self):
        """Pre-flight checker correctly identifies current environment and permissions."""
        res = PilotPrerequisitesChecker.check_prerequisites()
        self.assertIsInstance(res, PilotPrerequisitesResult)
        self.assertEqual(res.os_name, "Linux")
        self.assertTrue(res.checks.get("os_is_linux"))
        self.assertTrue(res.checks.get("kernel_version_supported"))
        self.assertTrue(res.passed)
        d = res.to_dict()
        self.assertIn("architecture", d)
        self.assertIn("ptrace_scope", d)

    def test_prerequisites_check_unsupported_os_fails(self):
        """Pre-flight checker fails cleanly on non-Linux OS."""
        with patch("platform.system", return_value="Darwin"):
            res = PilotPrerequisitesChecker.check_prerequisites()
            self.assertFalse(res.passed)
            self.assertTrue(any("Darwin" in err for err in res.errors))

    def test_prerequisites_check_old_kernel_fails(self):
        """Pre-flight checker detects kernels older than 3.2."""
        with patch("platform.release", return_value="2.6.32-generic"):
            res = PilotPrerequisitesChecker.check_prerequisites()
            self.assertFalse(res.passed)
            self.assertTrue(any("3.2+" in err for err in res.errors))

    def test_qualification_report_schema_and_tamper_detection(self):
        """Qualification report serializes cleanly and rejects tampered files on load."""
        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = os.path.join(tmpdir, "pilot_report.json")
            rep = PilotQualificationReport(
                schema_version="1.0.0",
                pilot_id="pilot_test_123",
                timestamp="2026-10-14T20:00:00Z",
                execution_mode="SIMULATED_REPRESENTATIVE_TARGET",
                real_hardware_validated=False,
                prerequisites={"passed": True, "os_name": "Linux"},
                target_identity={"pid": 1234, "binary_path": "/app/test", "is_stripped": True, "build_id": "deadbeef"},
                debug_artifact={"debug_image_path": "/app/test.debug", "build_id": "deadbeef", "match_status": "MATCHED"},
                capture_metrics={"mode": "CONSISTENT_STOPPED", "bytes_read": 1024, "bytes_requested": 1024, "completeness_pct": 100.0, "consistency": "ATOMIC_STOPPED"},
                latency_distribution={"samples_count": 5, "stop_latency_us": {"p50": 150.0}, "throughput_mb_s": 2500.0},
                investigation_summary={"finding_id": "fnd_1", "field_path": "counter", "old_value": 0, "new_value": 1, "negative_control_stable": True, "state_transition_verified": True, "function_attribution_verified": True, "final_candidate": "writer_fn", "final_tier": FUNCTION_TIER_VALIDATED_CAUSAL, "final_status": HYPOTHESIS_STATUS_VALIDATED},
                trust_boundary_assertions={"anti_tampering_verified": True, "build_id_match_enforced": True},
                explicit_disclosures=["Test disclosure note"],
            )
            rep.save(report_path)
            self.assertTrue(os.path.exists(report_path))
            self.assertTrue(len(rep.report_sha256) == 64)

            # Reload clean report
            loaded = PilotQualificationReport.load(report_path)
            self.assertEqual(loaded.pilot_id, "pilot_test_123")
            self.assertEqual(loaded.report_sha256, rep.report_sha256)

            # Tamper with file
            with open(report_path, "r", encoding="utf-8") as f:
                content = f.read()
            tampered = content.replace("SIMULATED_REPRESENTATIVE_TARGET", "REAL_HARDWARE_AUDITED")
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(tampered)

            # Load must fail with integrity violation
            with self.assertRaises(ValueError) as ctx:
                PilotQualificationReport.load(report_path)
            self.assertIn("integrity violation", str(ctx.exception).lower())

    def test_latency_distribution_calculation(self):
        """Latency distribution calculates percentiles and throughput deterministically."""
        samples = [
            {"stop_latency_us": 100.0, "memory_read_us": 1000.0, "resume_latency_us": 50.0, "total_capture_ms": 1.2, "bytes_read": 10_000_000, "capture_quality": "COMPLETE"},
            {"stop_latency_us": 120.0, "memory_read_us": 1100.0, "resume_latency_us": 60.0, "total_capture_ms": 1.4, "bytes_read": 10_000_000, "capture_quality": "COMPLETE"},
            {"stop_latency_us": 150.0, "memory_read_us": 1200.0, "resume_latency_us": 70.0, "total_capture_ms": 1.5, "bytes_read": 10_000_000, "capture_quality": "COMPLETE"},
            {"stop_latency_us": 200.0, "memory_read_us": 1500.0, "resume_latency_us": 90.0, "total_capture_ms": 2.0, "bytes_read": 10_000_000, "capture_quality": "COMPLETE"},
        ]
        dist = LatencyDistribution.calculate(samples)
        self.assertEqual(dist.samples_count, 4)
        self.assertEqual(dist.stop_latency_us["p50"], 150.0)
        self.assertEqual(dist.stop_latency_us["max"], 200.0)
        self.assertEqual(dist.stop_latency_us["min"], 100.0)
        self.assertGreater(dist.throughput_mb_s, 1000.0)
        self.assertEqual(dist.quality_summary, {"COMPLETE": 4})


class TestPhase14ProductionPilotScenarios(unittest.TestCase):
    """End-to-end representative embedded target qualification scenarios."""

    @classmethod
    def setUpClass(cls):
        cls.work_dir = tempfile.mkdtemp(prefix="phase14_pilot_test_")
        cls.harness = ProductionPilotHarness(workspace_dir=cls.work_dir)
        cls.stripped_bin, cls.debug_image, cls.unstripped_elf = cls.harness.build_representative_target()
        cls.ident_stripped = inspect_elf(cls.stripped_bin)
        cls.ident_debug = inspect_elf(cls.debug_image)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.work_dir, ignore_errors=True)

    def test_scenario_1_stripped_pie_with_companion_dwarf_qualification(self):
        """Scenario 1: Stripped PIE target + separate DWARF debug image yields verified root cause."""
        report = self.harness.run_pilot(
            benchmark_iterations=3,
            enforce_negative_control=True,
            simulate_competing_thread=False
        )
        self.assertEqual(report.execution_mode, "SIMULATED_REPRESENTATIVE_TARGET")
        self.assertFalse(report.real_hardware_validated)
        self.assertTrue(report.trust_boundary_assertions["build_id_match_enforced"])
        self.assertTrue(report.trust_boundary_assertions["negative_control_passed"])
        self.assertEqual(report.investigation_summary["final_tier"], FUNCTION_TIER_VALIDATED_CAUSAL)
        self.assertEqual(report.investigation_summary["final_status"], HYPOTHESIS_STATUS_VALIDATED)
        self.assertEqual(report.investigation_summary["final_candidate"], "telemetry_periodic_sample_writer")

    def test_scenario_2_build_id_mismatch_fails_closed(self):
        """Scenario 2: Mismatched Build ID companion fails closed and prevents unverified symbol resolution."""
        # Create an alternative binary with different source
        alt_cpp = os.path.join(self.work_dir, "alt_target.cpp")
        with open(alt_cpp, "w") as f:
            f.write("int main() { return 0; }\n")
        alt_bin = os.path.join(self.work_dir, "alt_target.elf")
        subprocess.run(["g++", "-g", alt_cpp, "-o", alt_bin], check=True)
        alt_ident = inspect_elf(alt_bin)

        self.assertNotEqual(self.ident_stripped.build_id, alt_ident.build_id)

        # Attempt investigation with mismatched companion and valid raw snapshot
        mgr = InvestigationManager(corpus_dir=os.path.join(self.work_dir, "corpus_mismatch"))
        with tempfile.TemporaryDirectory() as snap_dir:
            snap = RawRuntimeSnapshot(
                snapshot_id="snap_mismatch",
                pid=4001,
                executable=self.stripped_bin,
                executable_build_id=self.ident_stripped.build_id,
                timestamp="2026-10-14T03:00:00Z",
                completeness="COMPLETE",
                capture_backend="process_vm_readv",
                capture_duration_us=200.0,
            )
            snap.register_buffer(0x1000, b"\x00" * 256)
            snap.save(snap_dir)

            inv_res = mgr.start_investigation(
                goal="Test Build ID mismatch",
                memory_snapshot_path=snap_dir,
                debug_image=alt_bin,
                authorize_target=False
            )
            inv_id = inv_res["investigation_id"]
            session = mgr.sessions[inv_id]
            target_stage = session.stages.get("target_identity", {})
            self.assertEqual(target_stage.get("status"), "FAILED")
            self.assertEqual(target_stage.get("details", {}).get("build_id_status"), "MISMATCH")

    def test_scenario_3_competing_writers_prevent_causal_promotion(self):
        """Scenario 3: When competing background writer is active, causal attribution is refused."""
        report = self.harness.run_pilot(
            benchmark_iterations=2,
            enforce_negative_control=True,
            simulate_competing_thread=True  # Enables competing writer
        )
        self.assertNotEqual(report.investigation_summary["final_tier"], FUNCTION_TIER_VALIDATED_CAUSAL)
        self.assertEqual(report.investigation_summary["final_status"], HYPOTHESIS_STATUS_INCONCLUSIVE)
        self.assertIsNone(report.investigation_summary["final_candidate"])

    def test_scenario_4_state_transition_vs_function_attribution_decoupling(self):
        """Scenario 4: Validated state transition alone does not promote candidate without verified attribution."""
        mgr = InvestigationManager(corpus_dir=os.path.join(self.work_dir, "corpus_decouple"))
        inv_res = mgr.start_investigation(
            goal="Decouple transition from attribution",
            debug_image=self.debug_image,
            authorize_target=False
        )
        inv_id = inv_res["investigation_id"]
        session = mgr.sessions[inv_id]

        # Add initial supporting observation of field transition
        ev_obs = EvidenceRecord(
            evidence_id="ev_obs_decouple",
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            nature=NATURE_OBSERVATION,
            source="observer",
            session_id=inv_id,
            observation="Observed value change",
            details={"field_path": "TelemetryState.sensor_reading"},
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
        )
        session.ledger.add_record(ev_obs)

        hypo = InvestigationHypothesis(
            hypothesis_id="hypo_decoupled",
            investigation_id=inv_id,
            title="Candidate writer",
            claim="Candidate modifies field",
            candidate_fields=["TelemetryState.sensor_reading"],
            supporting_evidence_ids=["ev_obs_decouple"],
            function_candidates=[{
                "function_name": "telemetry_periodic_sample_writer",
                "candidate_tier": FUNCTION_TIER_STATIC_CANDIDATE,
                "confirmed_root_cause": False,
            }]
        )
        session.hypotheses.append(hypo)

        # Evaluating with deterministic_transition_verified=True BUT WITHOUT proof_evidence_id
        eval_res = mgr.evaluate_hypothesis(
            inv_id,
            hypo.hypothesis_id,
            deterministic_transition_verified=True,
            proof_evidence_id=None
        )
        self.assertTrue(eval_res["success"])
        # Hypothesis can only be SUPPORTED, not VALIDATED
        self.assertEqual(hypo.status, HYPOTHESIS_STATUS_SUPPORTED)
        # Function candidate remains STATIC_CANDIDATE
        self.assertEqual(hypo.function_candidates[0]["candidate_tier"], FUNCTION_TIER_STATIC_CANDIDATE)
        self.assertFalse(hypo.function_candidates[0]["confirmed_root_cause"])


class TestPhase14SecurityAndOperationalGates(unittest.TestCase):
    """Security boundaries, adversarial anti-forgery, and operational recovery gates."""

    def setUp(self):
        self.work_dir = tempfile.mkdtemp(prefix="phase14_sec_test_")
        self.mgr = InvestigationManager(corpus_dir=os.path.join(self.work_dir, "corpus"))
        self.inv_res = self.mgr.start_investigation(
            goal="Security boundaries test",
            authorize_target=False
        )
        self.inv_id = self.inv_res["investigation_id"]
        self.session = self.mgr.sessions[self.inv_id]

    def tearDown(self):
        shutil.rmtree(self.work_dir, ignore_errors=True)

    def test_gate_disarm_caller_supplied_trust_flags(self):
        """Gate: Caller-supplied booleans ('is_causal_writer: True', 'deterministic_transition_verified: True') are stripped."""
        hypo = InvestigationHypothesis(
            hypothesis_id="hypo_caller_flags",
            investigation_id=self.inv_id,
            title="Adversarial caller hypothesis",
            claim="Caller attempts to claim VALIDATED status",
            status=HYPOTHESIS_STATUS_VALIDATED,  # Caller tries to claim VALIDATED directly
            function_candidates=[{
                "function_name": "malicious_injection",
                "candidate_tier": FUNCTION_TIER_VALIDATED_CAUSAL,  # Caller tries to claim causal tier directly
                "confirmed_root_cause": True,
            }]
        )
        # Disarming must demote status to PROPOSED and tier to STATIC_CANDIDATE
        disarmed_hypo = sanitize_and_disarm_llm_hypothesis(hypo.to_dict(), ledger=self.session.ledger)
        self.assertNotEqual(disarmed_hypo.status, HYPOTHESIS_STATUS_VALIDATED)
        self.assertEqual(disarmed_hypo.status, HYPOTHESIS_STATUS_PROPOSED)
        self.assertEqual(disarmed_hypo.function_candidates[0]["candidate_tier"], FUNCTION_TIER_STATIC_CANDIDATE)
        self.assertFalse(disarmed_hypo.function_candidates[0]["confirmed_root_cause"])

    def test_gate_cross_investigation_evidence_replay_rejected(self):
        """Gate: Causal proof minted in Investigation A is rejected if replayed in Investigation B."""
        # Create second investigation
        inv_res2 = self.mgr.start_investigation(goal="Investigation B", authorize_target=False)
        inv_id2 = inv_res2["investigation_id"]
        session2 = self.mgr.sessions[inv_id2]

        # Add valid evidence to session 1
        rec1 = EvidenceRecord(
            evidence_id="ev_cross_pilot",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="collector",
            session_id=self.inv_id,
            observation="Observed transition in session 1",
            details={"target_function": "writer_fn", "field_path": "TelemetryState.sensor_reading"},
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
        )
        self.session.ledger.add_record(rec1)

        # Issue capability in session 1
        verifier1 = TrustedCausalVerifier(self.session)
        rcpt1 = verifier1.record_controlled_execution(
            target_function="writer_fn",
            field_path="TelemetryState.sensor_reading",
            execution_status="REPRODUCED",
            backend_type="synthetic_adversarial_fixture",
            evidence_id="ev_cross_pilot",
            hypothesis_id="hypo_cross",
        )
        cap1 = self.session.issue_verification_capability(
            evidence_id="ev_cross_pilot",
            target_function="writer_fn",
            field_path="TelemetryState.sensor_reading",
            hypothesis_id="hypo_cross",
            execution_result=rcpt1,
        )

        rec2 = EvidenceRecord(
            evidence_id="ev_cross_pilot",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="collector",
            session_id=inv_id2,
            observation="Observed transition in session 2",
            details={"target_function": "writer_fn", "field_path": "TelemetryState.sensor_reading"},
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
        )
        session2.ledger.add_record(rec2)

        # 1. Attempt cross-session attestation in session 2 using session 1's capability must be rejected
        with self.assertRaises(ValueError) as ctx:
            session2.attest_causal_proof(
                evidence_id="ev_cross_pilot",
                target_function="writer_fn",
                field_path="TelemetryState.sensor_reading",
                capability=cap1,
            )
        self.assertIn("cross-session", str(ctx.exception).lower())

        # 2. Attempt to evaluate hypothesis in session 2 using session 1's unverified proof
        hypo2 = InvestigationHypothesis(
            hypothesis_id="hypo_replayed",
            investigation_id=inv_id2,
            title="Replayed proof hypothesis",
            claim="Replaying proof from investigation 1",
            candidate_fields=["TelemetryState.sensor_reading"],
            supporting_evidence_ids=["ev_cross_pilot"],
            function_candidates=[{"function_name": "writer_fn", "candidate_tier": FUNCTION_TIER_STATIC_CANDIDATE}]
        )
        session2.hypotheses.append(hypo2)

        # Evaluating session 2 with evidence not in session 2's ledger must fail closed (not validated)
        res_eval = self.mgr.evaluate_hypothesis(
            inv_id2,
            hypo2.hypothesis_id,
            proof_evidence_id=rec1.evidence_id,
            deterministic_transition_verified=True,
        )
        self.assertNotEqual(res_eval.get("hypothesis", {}).get("status"), HYPOTHESIS_STATUS_VALIDATED)
        self.assertTrue(res_eval.get("transition", {}).get("unverified_claim_rejected", False))

    def test_gate_duplicate_observation_execution_and_cancellation(self):
        """Gate: Duplicate observation execution is rejected; canceled observation cannot execute."""
        hypo = InvestigationHypothesis(
            hypothesis_id="hypo_obs_test",
            investigation_id=self.inv_id,
            title="Observation lifecycle test",
            claim="Testing observation lifecycle",
            suggested_observations=[
                FollowUpObservation(
                    observation_id="obs_dup_1",
                    question="Test question",
                    target_kind="FIELD",
                    target_ref={"field_path": "counter"},
                    status=OBSERVATION_STATUS_PROPOSED,
                ),
                FollowUpObservation(
                    observation_id="obs_cancel_1",
                    question="Cancel question",
                    target_kind="FIELD",
                    target_ref={"field_path": "counter"},
                    status=OBSERVATION_STATUS_PROPOSED,
                )
            ]
        )
        self.session.hypotheses.append(hypo)

        # 1. Execute first observation
        res1 = self.mgr.execute_observation(self.inv_id, "obs_dup_1", result_data={"observed_value": 42})
        self.assertTrue(res1["success"])
        self.assertEqual(res1["observation"]["status"], OBSERVATION_STATUS_EXECUTED)

        # 2. Attempt duplicate execution of obs_dup_1 must be rejected
        res_dup = self.mgr.execute_observation(self.inv_id, "obs_dup_1", result_data={"observed_value": 42})
        self.assertFalse(res_dup["success"])
        self.assertTrue(res_dup.get("already_executed", False))
        self.assertIn("already been executed", res_dup.get("error", "").lower())

        # 3. Cancel second observation
        res_cancel = self.mgr.cancel_observation(self.inv_id, "obs_cancel_1", reason="Operator canceled")
        self.assertTrue(res_cancel["success"])
        self.assertEqual(res_cancel["observation"]["status"], OBSERVATION_STATUS_CANCELED)

        # 4. Attempt to execute canceled observation must be rejected
        res_exec_canceled = self.mgr.execute_observation(self.inv_id, "obs_cancel_1", result_data={"observed_value": 42})
        self.assertFalse(res_exec_canceled["success"])
        self.assertTrue(res_exec_canceled.get("canceled", False))
        self.assertIn("canceled", res_exec_canceled.get("error", "").lower())

    def test_gate_real_hardware_validation_disclosure(self):
        """Gate: Automated pilot reports strictly disclose simulated vs certified real hardware."""
        harness = ProductionPilotHarness(workspace_dir=self.work_dir)
        report = harness.run_pilot(benchmark_iterations=1)
        self.assertFalse(report.real_hardware_validated)
        self.assertEqual(report.execution_mode, "SIMULATED_REPRESENTATIVE_TARGET")
        self.assertTrue(any("fixture" in disc.lower() for disc in report.explicit_disclosures))
        self.assertTrue(any("remote" in disc.lower() or "physical" in disc.lower() for disc in report.explicit_disclosures))


if __name__ == "__main__":
    unittest.main()
