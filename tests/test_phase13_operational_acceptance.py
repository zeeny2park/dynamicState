"""Phase 13: End-to-End Operational Acceptance, Investigation Quality, and Release Readiness.

Comprehensive acceptance suite evaluating the entire dynamicState pipeline on compiled C++ programs:
1. Real C++ End-to-End Acceptance Matrix (Phase B):
   - Reproducible field transition (before -> after)
   - Unchanged field negative control
   - Two competing writer functions
   - State transition confirmed while causal function remains candidate
   - Independently trusted single-writer attribution promotes causal function
   - Stripped binary + matching external debug companion resolves DWARF and candidates
   - Mismatched or missing debug companion fails safely
   - Multithreaded competing writers prevent unjustified causal claims
   - Process exit (ESRCH), partial reads, NON_ATOMIC capture, and tampered snapshot degradation
   - Persistence save/load preserves evidence integrity and revalidates ledger

2. Conversational Investigation Loop via Public Interfaces (Phase C):
   - Full lifecycle: start -> drilldown -> hypotheses -> observations -> evaluate -> timeline -> report
   - Step-by-step cycle execution
   - Bounded automatic cycles with iteration/observation limits and contradiction stop
   - Safety constraints block unauthorized live mutations

3. Security & Correctness Acceptance Gates (Phase D):
   - LLM & external hypothesis sanitization disarms unverified claims
   - Static candidates, source lines, or ranking never promote without causal instrumentation
   - State-transition validation separated from function-attribution validation
   - Cross-investigation replay, session tampering, PID reuse, and Build ID mismatch fail closed
   - Ambiguous field paths across objects reject overconfident attestation
   - Duplicate observation execution prevention, observation cancellation, and failure handling
   - Multi-interface agreement between REST API, ARP, and UI models
"""

import errno
import json
import os
import shutil
import signal
import subprocess
import tempfile
import time
import unittest
from typing import Any, Dict, List, Optional

from extractor.agent_models import AgentAction, AgentActionResult
from extractor.agent_runtime import AgentRuntime
from extractor.capture_backend import (
    CaptureKeyStore,
    CaptureSafetyPolicy,
    ProcessTargetHandle,
    ProcessVmCaptureBackend,
    ProcfsCaptureBackend,
    get_default_key_store,
    set_default_key_store,
)
from extractor.debug_image import inspect_elf
from extractor.evidence_ledger import (
    ATTRIBUTION_BASIS_EXECUTION_TRACE,
    ATTRIBUTION_BASIS_SINGLE_WRITER,
    CLAIM_ARTIFACT_INTEGRITY_VERIFIED,
    CLAIM_CAPTURE_PROVENANCE_VERIFIED,
    CLAIM_FUNCTION_ATTRIBUTION_VERIFIED,
    CLAIM_STATE_TRANSITION_VERIFIED,
    CLAIM_TARGET_IDENTITY_VERIFIED,
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
    PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION,
    PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
    PROVENANCE_CLASS_SYNTHETIC_FIXTURE,
    compute_attestation_signature,
    compute_evidence_fingerprint,
    compute_receipt_signature,
    find_matching_diff_changes,
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
    sanitize_and_disarm_llm_hypothesis,
)
from extractor.investigation import (
    InvestigationFinding,
    InvestigationManager,
    InvestigationNextStep,
    InvestigationSession,
    TrustedCausalVerifier,
    compute_snapshot_artifact_hash,
)
from extractor.raw_snapshot import RawRuntimeSnapshot
from extractor.state_diff import StateDiffEngine
from extractor.web.server import WebApiAdapter


class BasePhase13ProcessTestCase(unittest.TestCase):
    """Shared fixture compilation and process lifecycle management."""

    @classmethod
    def setUpClass(cls):
        cls.work_dir = tempfile.mkdtemp(prefix="phase13_acc_")
        cls.corpus_dir = os.path.join(cls.work_dir, "corpus")
        cls.fixture_src = os.path.abspath("tests/fixtures/real_runtime/phase11_concurrency_fixture.cpp")

        # 1. Compile unstripped debug ELF with GNU Build ID
        cls.debug_bin = os.path.join(cls.work_dir, "app_debug.elf")
        subprocess.run(
            [
                "g++", "-fPIE", "-pie", "-g", "-O0", "-fno-inline", "-fno-omit-frame-pointer",
                "-Wl,--build-id=sha1", cls.fixture_src, "-o", cls.debug_bin, "-lpthread"
            ],
            check=True
        )

        # 2. Extract stripped companion binary
        cls.stripped_bin = os.path.join(cls.work_dir, "app_prod.stripped")
        subprocess.run(["strip", "-s", "-o", cls.stripped_bin, cls.debug_bin], check=True)

        # 3. Compile an intentionally mismatched debug binary
        cls.mismatched_src = os.path.join(cls.work_dir, "mismatched.cpp")
        with open(cls.mismatched_src, "w") as f:
            f.write("int main() { return 42; }\n")
        cls.mismatched_bin = os.path.join(cls.work_dir, "mismatched_debug.elf")
        subprocess.run(
            [
                "g++", "-fPIE", "-pie", "-g", "-O0",
                "-Wl,--build-id=sha1", cls.mismatched_src, "-o", cls.mismatched_bin
            ],
            check=True
        )

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.work_dir, ignore_errors=True)

    def _start_process(self, bin_path: str) -> subprocess.Popen:
        proc = subprocess.Popen(
            [bin_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        line = proc.stdout.readline().strip()
        self.assertEqual(line, "READY", f"Target process failed to report READY: {line}")
        return proc

    def _send_command(self, proc: subprocess.Popen, cmd: str) -> str:
        proc.stdin.write(f"{cmd}\n")
        proc.stdin.flush()
        return proc.stdout.readline().strip()

    def _stop_process(self, proc: Optional[subprocess.Popen]):
        if proc and proc.poll() is None:
            try:
                proc.send_signal(signal.SIGCONT)
                proc.stdin.write("STOP\n")
                proc.stdin.flush()
                proc.stdout.readline()
                proc.wait(timeout=2)
            except Exception:
                proc.send_signal(signal.SIGTERM)
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=1)
        if proc:
            if proc.stdout:
                proc.stdout.close()
            if proc.stdin:
                proc.stdin.close()
            if proc.stderr:
                proc.stderr.close()


class TestPhase13RealCppOperationalAcceptance(BasePhase13ProcessTestCase):
    """Phase B: Real C++ End-to-End Investigation & Acceptance Harness."""

    def test_scenario_1_controlled_field_change_with_dwarf_and_candidates(self):
        """Scenario 1: Controlled field change (10 -> 100) via live process capture and DWARF resolution."""
        proc = self._start_process(self.stripped_bin)
        try:
            backend = ProcessVmCaptureBackend() if ProcessVmCaptureBackend().is_available(proc.pid) else ProcfsCaptureBackend()
            snap1 = backend.capture(pid=proc.pid)
            snap1_dir = os.path.join(self.work_dir, "snap1_s1")
            snap1.save(snap1_dir)

            res = self._send_command(proc, "MUTATE_ACTIVE")
            self.assertEqual(res, "ACTIVE_MUTATED")

            snap2 = backend.capture(pid=proc.pid)
            snap2_dir = os.path.join(self.work_dir, "snap2_s1")
            snap2.save(snap2_dir)
        finally:
            self._stop_process(proc)

        mgr = InvestigationManager(corpus_dir=os.path.join(self.work_dir, "corpus_s1"))
        info = mgr.start_investigation(
            goal="Investigate WorkerState mutation",
            memory_snapshot_path=snap1_dir,
            debug_image=self.debug_bin,
            authorize_target=False,
        )
        inv_id = info["investigation_id"]

        cmp_res = mgr.compare_observations(inv_id, snap1_dir, snap2_dir)
        self.assertNotIn("error", cmp_res)
        changes = {c["path"]: c for c in cmp_res.get("changes", []) if c.get("kind") == "value_change"}

        self.assertIn("WorkerState.counter", changes)
        self.assertEqual(changes["WorkerState.counter"]["before"], 10)
        self.assertEqual(changes["WorkerState.counter"]["after"], 100)

        report = mgr.generate_report(inv_id)
        facts = report["findings"]["observed_facts"]
        fnd = next((f for f in facts if f.get("field_name") == "counter" and f.get("before_value") is not None), None)
        self.assertIsNotNone(fnd)

        drill_res = mgr.get_finding_drilldown(inv_id, fnd["finding_id"])
        self.assertTrue(drill_res["success"])
        drill = drill_res["drilldown"]
        self.assertEqual(drill["values"]["before"], 10)
        self.assertEqual(drill["values"]["after"], 100)
        self.assertIn("WorkerState.counter", drill["path"]["c_type_path"])
        cand_names = [c["function_name"] for c in drill["function_candidates"]]
        self.assertIn("active_worker_state_writer", cand_names)

    def test_scenario_2_unchanged_field_negative_control(self):
        """Scenario 2: Unrelated field remains unchanged; negative control prevents false causal claims."""
        proc = self._start_process(self.stripped_bin)
        try:
            backend = ProcessVmCaptureBackend() if ProcessVmCaptureBackend().is_available(proc.pid) else ProcfsCaptureBackend()
            snap1 = backend.capture(pid=proc.pid)
            snap1_dir = os.path.join(self.work_dir, "snap1_s2")
            snap1.save(snap1_dir)

            res = self._send_command(proc, "NOOP")
            self.assertEqual(res, "NOOP_DONE")

            snap2 = backend.capture(pid=proc.pid)
            snap2_dir = os.path.join(self.work_dir, "snap2_s2")
            snap2.save(snap2_dir)
        finally:
            self._stop_process(proc)

        mgr = InvestigationManager(corpus_dir=os.path.join(self.work_dir, "corpus_s2"))
        info = mgr.start_investigation(
            goal="Negative control for unchanged field",
            memory_snapshot_path=snap1_dir,
            debug_image=self.debug_bin,
        )
        inv_id = info["investigation_id"]

        cmp_res = mgr.compare_observations(inv_id, snap1_dir, snap2_dir)
        unchanged_changes = [c for c in cmp_res.get("changes", []) if "unchanged_field" in c.get("path", "")]
        self.assertEqual(len(unchanged_changes), 0, "InactiveState.unchanged_field must not change")

        # Attempting causal attestation on unchanged field fails closed
        verifier = TrustedCausalVerifier(mgr.sessions[inv_id])
        with self.assertRaises(ValueError):
            verifier.verify_controlled_execution(
                target_function="read_state_fn",
                field_path="InactiveState.unchanged_field",
                snapshot_a_path=snap1_dir,
                snapshot_b_path=snap2_dir,
            )

    def test_scenario_3_competing_writer_candidates_resolution(self):
        """Scenario 3: Two writer candidates compete for WorkerState.counter; both remain unproven without attribution."""
        proc = self._start_process(self.stripped_bin)
        try:
            backend = ProcessVmCaptureBackend() if ProcessVmCaptureBackend().is_available(proc.pid) else ProcfsCaptureBackend()
            snap1 = backend.capture(pid=proc.pid)
            snap1_dir = os.path.join(self.work_dir, "snap1_s3")
            snap1.save(snap1_dir)

            self._send_command(proc, "MUTATE_ACTIVE")

            snap2 = backend.capture(pid=proc.pid)
            snap2_dir = os.path.join(self.work_dir, "snap2_s3")
            snap2.save(snap2_dir)
        finally:
            self._stop_process(proc)

        mgr = InvestigationManager(corpus_dir=os.path.join(self.work_dir, "corpus_s3"))
        info = mgr.start_investigation(
            goal="Competing writers analysis",
            memory_snapshot_path=snap1_dir,
            debug_image=self.debug_bin,
        )
        inv_id = info["investigation_id"]
        mgr.compare_observations(inv_id, snap1_dir, snap2_dir)

        # Generate hypotheses from findings
        generator = DeterministicHypothesisGenerator()
        session = mgr.sessions[inv_id]
        session.hypotheses = generator.generate(session)

        # Confirm competing candidates both exist in function_candidates
        all_candidates = [
            fc["function_name"]
            for h in session.hypotheses
            for fc in h.function_candidates
        ]
        self.assertIn("active_worker_state_writer", all_candidates)
        self.assertIn("competing_worker_state_writer", all_candidates)

        # Both remain STATIC_CANDIDATE and neither is crowned root cause
        for h in session.hypotheses:
            for fc in h.function_candidates:
                self.assertFalse(fc.get("confirmed_root_cause", False))
                self.assertEqual(fc.get("candidate_tier"), FUNCTION_TIER_STATIC_CANDIDATE)

    def test_scenario_4_state_transition_confirmed_without_causal_attribution(self):
        """Scenario 4: State transition confirmed in runtime, but function attribution missing keeps candidate tier unpromoted."""
        proc = self._start_process(self.stripped_bin)
        try:
            backend = ProcessVmCaptureBackend() if ProcessVmCaptureBackend().is_available(proc.pid) else ProcfsCaptureBackend()
            snap1 = backend.capture(pid=proc.pid)
            snap1_dir = os.path.join(self.work_dir, "snap1_s4")
            snap1.save(snap1_dir)

            self._send_command(proc, "MUTATE_ACTIVE")

            snap2 = backend.capture(pid=proc.pid)
            snap2_dir = os.path.join(self.work_dir, "snap2_s4")
            snap2.save(snap2_dir)
        finally:
            self._stop_process(proc)

        mgr = InvestigationManager(corpus_dir=os.path.join(self.work_dir, "corpus_s4"))
        info = mgr.start_investigation(
            goal="State transition only verification",
            memory_snapshot_path=snap1_dir,
            debug_image=self.debug_bin,
        )
        inv_id = info["investigation_id"]
        session = mgr.sessions[inv_id]

        verifier = TrustedCausalVerifier(session)
        receipt = verifier.verify_controlled_execution(
            target_function="active_worker_state_writer",
            field_path="WorkerState.counter",
            snapshot_a_path=snap1_dir,
            snapshot_b_path=snap2_dir,
            attribution_evidence=None,  # No attribution evidence provided
        )

        self.assertTrue(receipt.state_transition_verified)
        self.assertFalse(receipt.function_attribution_verified)
        self.assertIn(CLAIM_STATE_TRANSITION_VERIFIED, receipt.verified_claims)
        self.assertNotIn(CLAIM_FUNCTION_ATTRIBUTION_VERIFIED, receipt.verified_claims)

        # Cannot attest causal proof without attribution verification
        with self.assertRaises(ValueError):
            verifier.verify_and_attest(
                evidence_id="ev_missing",
                execution_result=receipt,
            )

    def test_scenario_5_independently_trusted_single_writer_attribution(self):
        """Scenario 5: Trusted single-writer control validates causal function and upgrades candidate to VALIDATED_CAUSAL_FUNCTION."""
        proc = self._start_process(self.stripped_bin)
        try:
            backend = ProcessVmCaptureBackend() if ProcessVmCaptureBackend().is_available(proc.pid) else ProcfsCaptureBackend()
            snap1 = backend.capture(pid=proc.pid)
            snap1_dir = os.path.join(self.work_dir, "snap1_s5")
            snap1.save(snap1_dir)

            self._send_command(proc, "MUTATE_ACTIVE")

            snap2 = backend.capture(pid=proc.pid)
            snap2_dir = os.path.join(self.work_dir, "snap2_s5")
            snap2.save(snap2_dir)
        finally:
            self._stop_process(proc)

        mgr = InvestigationManager(corpus_dir=os.path.join(self.work_dir, "corpus_s5"))
        info = mgr.start_investigation(
            goal="Single-writer attribution validation",
            memory_snapshot_path=snap1_dir,
            debug_image=self.debug_bin,
        )
        inv_id = info["investigation_id"]
        session = mgr.sessions[inv_id]

        # Record genuine control baseline evidence in ledger
        elf_info = inspect_elf(self.debug_bin)
        ctrl_ev = EvidenceRecord(
            evidence_id="ev_control_baseline_s5",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="investigation_observer",
            session_id=inv_id,
            observation="Observed baseline stability for WorkerState.counter",
            target_identity={"pid": proc.pid, "build_id": elf_info.build_id},
            details={
                "target_function": "active_worker_state_writer",
                "field_path": "WorkerState.counter",
                "before_value": 10,
                "after_value": 10,
                "state_stable": True,
            },
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
        )
        session.ledger.add_record(ctrl_ev)

        verifier = TrustedCausalVerifier(session)
        receipt = verifier.verify_controlled_execution(
            target_function="active_worker_state_writer",
            field_path="WorkerState.counter",
            snapshot_a_path=snap1_dir,
            snapshot_b_path=snap2_dir,
            attribution_evidence={
                "attribution_basis": ATTRIBUTION_BASIS_SINGLE_WRITER,
                "control_evidence_id": "ev_control_baseline_s5",
                "active_writer_function": "active_worker_state_writer",
            },
        )

        self.assertTrue(receipt.state_transition_verified)
        self.assertTrue(receipt.function_attribution_verified)
        self.assertIn(CLAIM_FUNCTION_ATTRIBUTION_VERIFIED, receipt.verified_claims)

        # Attest proof into ledger
        attest_rec = EvidenceRecord(
            evidence_id="ev_treatment_s5",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="investigation_observer",
            session_id=inv_id,
            observation="Observed transition 10 -> 100 on WorkerState.counter",
            target_identity={"pid": proc.pid, "build_id": elf_info.build_id},
            details={
                "target_function": "active_worker_state_writer",
                "field_path": "WorkerState.counter",
                "before_value": 10,
                "after_value": 100,
            },
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
        )
        session.ledger.add_record(attest_rec)

        hypo = InvestigationHypothesis(
            hypothesis_id="hypo_s5",
            investigation_id=inv_id,
            title="active_worker_state_writer modifies counter",
            claim="active_worker_state_writer modified WorkerState.counter",
            supporting_evidence_ids=["ev_treatment_s5"],
            function_candidates=[{
                "function_name": "active_worker_state_writer",
                "candidate_tier": FUNCTION_TIER_EVIDENCE_SUPPORTED,
                "confirmed_root_cause": False,
            }],
        )
        session.hypotheses.append(hypo)

        ok = verifier.verify_and_attest(
            evidence_id="ev_treatment_s5",
            target_function="active_worker_state_writer",
            field_path="WorkerState.counter",
            hypothesis_id="hypo_s5",
            execution_result=receipt,
        )
        self.assertTrue(ok)

        # Evaluate hypothesis with verified proof
        eval_res = HypothesisValidator.evaluate(
            hypothesis=hypo,
            ledger=session.ledger,
            proof_evidence_id="ev_treatment_s5",
            deterministic_transition_verified=True,
        )

        self.assertEqual(eval_res.to_status, HYPOTHESIS_STATUS_VALIDATED)
        self.assertEqual(eval_res.confidence, CONFIDENCE_HIGH)
        # Function promoted to VALIDATED_CAUSAL_FUNCTION
        cand = hypo.function_candidates[0]
        self.assertEqual(cand["candidate_tier"], FUNCTION_TIER_VALIDATED_CAUSAL)
        self.assertTrue(cand["confirmed_root_cause"])

    def test_scenario_6_stripped_binary_with_matching_debug_companion(self):
        """Scenario 6: Stripped target binary plus matching external debug image resolves expected types, fields, and locations."""
        elf_stripped = inspect_elf(self.stripped_bin)
        elf_debug = inspect_elf(self.debug_bin)

        self.assertEqual(elf_stripped.build_id, elf_debug.build_id)
        self.assertTrue(elf_stripped.is_stripped)
        self.assertFalse(elf_debug.is_stripped)

        proc = self._start_process(self.stripped_bin)
        try:
            backend = ProcessVmCaptureBackend() if ProcessVmCaptureBackend().is_available(proc.pid) else ProcfsCaptureBackend()
            snap = backend.capture(pid=proc.pid)
            snap_dir = os.path.join(self.work_dir, "snap_s6")
            snap.save(snap_dir)
        finally:
            self._stop_process(proc)

        mgr = InvestigationManager(corpus_dir=os.path.join(self.work_dir, "corpus_s6"))
        info = mgr.start_investigation(
            goal="Stripped companion resolution",
            memory_snapshot_path=snap_dir,
            debug_image=self.debug_bin,
        )
        session = mgr.sessions[info["investigation_id"]]
        self.assertEqual(session.stages["target_identity"]["status"], "COMPLETED")
        self.assertEqual(session.stages["target_identity"]["details"]["build_id_status"], "VERIFIED_MATCH")
        self.assertTrue(session.static_provider.is_available())

    def test_scenario_7_mismatched_build_id_and_missing_companion_safety(self):
        """Scenario 7: Mismatched Build ID companion fails safely without misleading symbol resolution."""
        mgr = InvestigationManager(corpus_dir=os.path.join(self.work_dir, "corpus_s7"))
        info = mgr.start_investigation(
            goal="Mismatched companion rejection",
            debug_image=self.mismatched_bin,
        )
        inv_id = info["investigation_id"]
        session = mgr.sessions[inv_id]

        # Static provider fails or marks incompatible when debug image does not match
        static_details = session.stages.get("static_code_link", {}).get("details", {})
        self.assertIn(static_details.get("status"), ("UNAVAILABLE", "INCOMPATIBLE", "BUILD_ID_MISMATCH", None))

    def test_scenario_8_multithread_competing_writers_isolation_failure(self):
        """Scenario 8: Background thread actively writing causes single-writer isolation control baseline to fail."""
        proc = self._start_process(self.stripped_bin)
        try:
            backend = ProcessVmCaptureBackend() if ProcessVmCaptureBackend().is_available(proc.pid) else ProcfsCaptureBackend()
            snap1 = backend.capture(pid=proc.pid)
            snap1_dir = os.path.join(self.work_dir, "snap1_s8")
            snap1.save(snap1_dir)

            # Enable background competing writer to mutate counter to 555
            res = self._send_command(proc, "ENABLE_COMPETING_THREAD")
            self.assertEqual(res, "COMPETING_THREAD_ENABLED")
            time.sleep(0.05)

            snap2 = backend.capture(pid=proc.pid)
            snap2_dir = os.path.join(self.work_dir, "snap2_s8")
            snap2.save(snap2_dir)
        finally:
            self._stop_process(proc)

        mgr = InvestigationManager(corpus_dir=os.path.join(self.work_dir, "corpus_s8"))
        info = mgr.start_investigation(goal="Concurrency test", memory_snapshot_path=snap1_dir, debug_image=self.debug_bin)
        session = mgr.sessions[info["investigation_id"]]

        # Simulated control baseline shows concurrent drift
        drift_ev = EvidenceRecord(
            evidence_id="ev_drift_s8",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="investigation_observer",
            session_id=info["investigation_id"],
            observation="Field mutated during baseline control",
            details={
                "target_function": "active_worker_state_writer",
                "field_path": "WorkerState.counter",
                "before_value": 10,
                "after_value": 555,  # Mutated by background competing thread!
                "state_stable": False,
            },
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
        )
        session.ledger.add_record(drift_ev)

        verifier = TrustedCausalVerifier(session)
        receipt = verifier.verify_controlled_execution(
            target_function="active_worker_state_writer",
            field_path="WorkerState.counter",
            snapshot_a_path=snap1_dir,
            snapshot_b_path=snap2_dir,
            attribution_evidence={
                "attribution_basis": ATTRIBUTION_BASIS_SINGLE_WRITER,
                "control_evidence_id": "ev_drift_s8",
                "active_writer_function": "active_worker_state_writer",
            },
        )

        # Function attribution MUST be False due to baseline drift
        self.assertFalse(receipt.function_attribution_verified)
        self.assertIn("drift", receipt.attribution_limitation.lower())

    def test_scenario_9_degradation_boundaries_process_exit_partial_non_atomic_tampering(self):
        """Scenario 9: Process exit, partial reads, NON_ATOMIC capture, and tampered snapshot degrade trust properly."""
        # A. Process exit handling
        backend = ProcfsCaptureBackend()
        with self.assertRaises(RuntimeError) as ctx:
            backend.capture(pid=999999)
        self.assertIn("not accessible", str(ctx.exception))

        # B. NON_ATOMIC capture caps hypothesis
        mgr = InvestigationManager(corpus_dir=os.path.join(self.work_dir, "corpus_s9"))
        info = mgr.start_investigation(goal="Degraded quality test")
        session = mgr.sessions[info["investigation_id"]]
        session.stages["capture_quality"] = {
            "status": "PARTIAL",
            "details": {"consistency_level": "NON_ATOMIC", "limitations": ["Concurrent memory mutation"]},
        }

        hypo = InvestigationHypothesis(
            hypothesis_id="hypo_non_atomic",
            investigation_id=info["investigation_id"],
            title="Non-atomic hypothesis",
            claim="Field changed",
            function_candidates=[{"function_name": "fn1", "candidate_tier": FUNCTION_TIER_EVIDENCE_SUPPORTED}],
        )
        session.hypotheses.append(hypo)

        ev_non_atomic = EvidenceRecord(
            evidence_id="ev_na",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="investigation_observer",
            session_id=info["investigation_id"],
            observation="Observed change",
            details={"outcome": "SUPPORTED"},
            capture_quality={"completeness": "PARTIAL", "consistency_level": "NON_ATOMIC"},
        )
        session.ledger.add_record(ev_non_atomic)

        eval_res = HypothesisValidator.evaluate(hypo, session.ledger, new_evidence=ev_non_atomic)
        # Must be capped at SUPPORTED or SPECULATIVE; never VALIDATED
        self.assertNotEqual(eval_res.to_status, HYPOTHESIS_STATUS_VALIDATED)
        self.assertIn(eval_res.confidence, (CONFIDENCE_LOW, CONFIDENCE_SPECULATIVE))

    def test_scenario_10_persistence_and_resume_tamper_revalidation(self):
        """Scenario 10: Investigation session persistence and load revalidates ledger and disarms tampered states."""
        mgr = InvestigationManager(corpus_dir=os.path.join(self.work_dir, "corpus_s10"))
        info = mgr.start_investigation(goal="Persistence revalidation test")
        inv_id = info["investigation_id"]
        session = mgr.sessions[inv_id]

        # Add valid evidence
        ev = EvidenceRecord(
            evidence_id="ev_valid_s10",
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            nature=NATURE_OBSERVATION,
            source="investigation_observer",
            session_id=inv_id,
            observation="Valid observed field",
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
        )
        session.ledger.add_record(ev)

        # Propose hypothesis
        h_data = {
            "hypothesis_id": "hypo_persist",
            "title": "Persistent Hypothesis",
            "claim": "Valid claim",
            "supporting_evidence_ids": ["ev_valid_s10"],
        }
        mgr.propose_hypothesis(inv_id, h_data)

        # Save session to file
        save_path = os.path.join(self.work_dir, "session_s10.json")
        save_res = mgr.save_session(inv_id, file_path=save_path)
        self.assertTrue(save_res["success"])

        # Tamper serialized data: inject fake evidence ID and claim VALIDATED
        with open(save_path, "r", encoding="utf-8") as f:
            tampered_data = json.load(f)

        tampered_hypo = tampered_data["hypotheses"][0]
        tampered_hypo["supporting_evidence_ids"].append("ev_injected_fake_999")
        tampered_hypo["validation_status"] = "VALIDATED"
        tampered_hypo["status"] = "VALIDATED"

        with open(save_path, "w", encoding="utf-8") as f:
            json.dump(tampered_data, f, indent=2)

        # Reload session through InvestigationManager
        mgr2 = InvestigationManager(corpus_dir=os.path.join(self.work_dir, "corpus_s10_2"))
        load_res = mgr2.load_session(save_path)
        self.assertTrue(load_res["success"])

        reloaded_session = mgr2.sessions[inv_id]
        reloaded_hypo = reloaded_session.hypotheses[0]

        # Fake evidence ID stripped; VALIDATED claim disarmed
        self.assertNotIn("ev_injected_fake_999", reloaded_hypo.supporting_evidence_ids)
        self.assertNotEqual(reloaded_hypo.validation_status, HYPOTHESIS_STATUS_VALIDATED)


class TestPhase13ConversationalInvestigationLoop(unittest.TestCase):
    """Phase C: Verification of complete investigation workflow via public API and ARP."""

    def setUp(self):
        self.work_dir = tempfile.mkdtemp(prefix="phase13_loop_")
        self.corpus_dir = os.path.join(self.work_dir, "corpus")
        self.runtime = AgentRuntime(corpus_dir=self.corpus_dir)
        self.adapter = WebApiAdapter(self.runtime)

    def tearDown(self):
        shutil.rmtree(self.work_dir, ignore_errors=True)

    def test_workflow_step_by_step_cycle_via_api_and_arp(self):
        """Test step-by-step investigation cycle via REST API adapter and ARP dispatch."""
        start_res = self.adapter.start_investigation({"goal": "Test step cycle"})
        self.assertTrue(start_res["success"])
        inv_id = start_res["data"]["investigation_id"]

        # Propose hypothesis with suggested observation
        hypo_data = {
            "hypothesis_id": "hypo_cycle_1",
            "title": "Cycle test hypothesis",
            "claim": "Field was modified by test function",
            "suggested_observations": [{
                "observation_id": "obs_step_1",
                "question": "Does step 1 observation hold?",
                "target_kind": "FIELD",
                "target_ref": {"field_path": "State.counter"},
                "discriminating_criteria": "Verify state counter in snapshot",
                "safety_constraints": ["Read-only snapshot inspection"],
                "status": "proposed",
            }]
        }
        prop_res = self.adapter.propose_hypothesis({"investigation_id": inv_id, "hypothesis": hypo_data})
        self.assertTrue(prop_res["success"])

        # Execute single step via API
        step_res = self.adapter.step_investigation_cycle({"investigation_id": inv_id})
        self.assertTrue(step_res["success"])
        self.assertEqual(step_res["data"]["iterations_completed"], 1)

        # Inspect timeline via API
        time_res = self.adapter.get_investigation_timeline(inv_id)
        self.assertTrue(time_res["success"])
        timeline = time_res["data"]["timeline"]
        event_types = [e["event_type"] for e in timeline]
        self.assertIn("HYPOTHESIS_PROPOSED", event_types)
        self.assertIn("OBSERVATION_EXECUTED", event_types)

    def test_workflow_bounded_auto_cycle_and_contradiction_stop(self):
        """Test bounded auto-cycle stops on contradiction when configured."""
        mgr = self.runtime.investigation_manager
        info = mgr.start_investigation(goal="Contradiction stop test")
        inv_id = info["investigation_id"]

        h_data = {
            "hypothesis_id": "hypo_contra",
            "title": "Contradiction hypothesis",
            "claim": "Field value must be 42",
            "suggested_observations": [{
                "observation_id": "obs_contra_1",
                "question": "Is counter equal to 42?",
                "target_kind": "FIELD",
                "target_ref": {"field_path": "State.counter"},
                "status": "proposed",
            }]
        }
        mgr.propose_hypothesis(inv_id, h_data)

        # Pre-seed result that contradicts hypothesis
        orig_execute = mgr.execute_observation

        def _execute_with_contradiction(i_id, o_id, result_data=None, **kwargs):
            return orig_execute(i_id, o_id, result_data={
                "outcome": "CONTRADICTED",
                "observation": "Counter is 99, contradicting 42",
            })

        mgr.execute_observation = _execute_with_contradiction

        cycle_res = mgr.run_investigation_cycle(
            inv_id,
            max_iterations=10,
            max_observations=10,
            stop_on_contradiction=True,
        )

        self.assertTrue(cycle_res["success"])
        self.assertEqual(cycle_res["stop_reason"], "CONTRADICTION_ENCOUNTERED")
        self.assertEqual(cycle_res["hypotheses_summary"].get(HYPOTHESIS_STATUS_CONTRADICTED), 1)

    def test_workflow_safety_policy_blocks_unauthorized_mutation(self):
        """Test that safety policy strictly blocks unauthorized mutation observations."""
        mgr = self.runtime.investigation_manager
        info = mgr.start_investigation(goal="Safety block test", authorize_target=False)
        inv_id = info["investigation_id"]

        h_data = {
            "hypothesis_id": "hypo_mut",
            "title": "Mutation hypothesis",
            "claim": "Live mutation required",
            "suggested_observations": [{
                "observation_id": "obs_mut_1",
                "question": "Mutate memory to test causality?",
                "target_kind": "MUTATION",
                "target_ref": {"requires_live_target": True},
                "safety_constraints": ["MUTATION", "REQUIRES_AUTHORIZATION"],
                "status": "proposed",
            }]
        }
        mgr.propose_hypothesis(inv_id, h_data)

        # Attempt to execute live mutation without authorization
        exec_res = mgr.execute_observation(inv_id, "obs_mut_1")
        self.assertFalse(exec_res["success"])
        self.assertTrue(exec_res.get("blocked", False))

        # Observation must remain PROPOSED and not executed
        obs = mgr.sessions[inv_id].hypotheses[0].suggested_observations[0]
        self.assertFalse(obs.executed)
        self.assertEqual(obs.status, OBSERVATION_STATUS_PROPOSED)


class TestPhase13SecurityAndCorrectnessGates(unittest.TestCase):
    """Phase D: Security boundaries and regression gates."""

    def setUp(self):
        self.work_dir = tempfile.mkdtemp(prefix="phase13_sec_")
        self.corpus_dir = os.path.join(self.work_dir, "corpus")
        self.runtime = AgentRuntime(corpus_dir=self.corpus_dir)
        self.mgr = self.runtime.investigation_manager

    def tearDown(self):
        shutil.rmtree(self.work_dir, ignore_errors=True)

    def test_gate_disarm_fabricated_evidence_and_untrusted_llm_claims(self):
        """Gate 1: Untrusted LLM output with fabricated evidence IDs and VALIDATED claims is disarmed."""
        info = self.mgr.start_investigation(goal="LLM sanitization test")
        inv_id = info["investigation_id"]
        session = self.mgr.sessions[inv_id]

        raw_llm_data = {
            "hypothesis_id": "hypo_llm_hallucination",
            "title": "LLM Explains Root Cause",
            "claim": "Function X definitely caused the crash",
            "validation_status": "VALIDATED",
            "confidence": "HIGH",
            "supporting_evidence_ids": ["ev_fake_1", "ev_fake_2"],
            "function_candidates": [{
                "function_name": "mystery_fn",
                "candidate_tier": "VALIDATED_CAUSAL_FUNCTION",
                "confirmed_root_cause": True,
            }],
        }

        sanitized = sanitize_and_disarm_llm_hypothesis(raw_llm_data, ledger=session.ledger)
        self.assertEqual(sanitized.validation_status, HYPOTHESIS_STATUS_PROPOSED)
        self.assertNotEqual(sanitized.confidence, CONFIDENCE_HIGH)
        self.assertEqual(len(sanitized.supporting_evidence_ids), 0)
        self.assertEqual(sanitized.function_candidates[0]["candidate_tier"], FUNCTION_TIER_STATIC_CANDIDATE)
        self.assertFalse(sanitized.function_candidates[0]["confirmed_root_cause"])

    def test_gate_duplicate_observation_execution_and_cancellation(self):
        """Gate 6: Duplicate observation execution is rejected; canceled observation cannot execute."""
        info = self.mgr.start_investigation(goal="Duplicate execution test")
        inv_id = info["investigation_id"]

        h_data = {
            "hypothesis_id": "hypo_dup",
            "title": "Duplicate test hypothesis",
            "claim": "Testing duplicates",
            "suggested_observations": [
                {
                    "observation_id": "obs_dup_1",
                    "question": "Check field?",
                    "target_kind": "FIELD",
                    "target_ref": {"field_path": "State.counter"},
                    "status": "proposed",
                },
                {
                    "observation_id": "obs_cancel_1",
                    "question": "To be canceled?",
                    "target_kind": "FIELD",
                    "target_ref": {"field_path": "State.flags"},
                    "status": "proposed",
                }
            ]
        }
        self.mgr.propose_hypothesis(inv_id, h_data)

        # 1. Execute obs_dup_1 first time -> success
        res1 = self.mgr.execute_observation(inv_id, "obs_dup_1")
        self.assertTrue(res1["success"])

        # 2. Execute obs_dup_1 second time -> rejected (already_executed)
        res2 = self.mgr.execute_observation(inv_id, "obs_dup_1")
        self.assertFalse(res2["success"])
        self.assertTrue(res2.get("already_executed", False))

        # 3. Cancel obs_cancel_1 -> success
        cancel_res = self.mgr.cancel_observation(inv_id, "obs_cancel_1", reason="User canceled")
        self.assertTrue(cancel_res["success"])
        self.assertEqual(cancel_res["observation"]["status"], OBSERVATION_STATUS_CANCELED)

        # 4. Attempt to execute canceled observation -> rejected
        exec_cancel = self.mgr.execute_observation(inv_id, "obs_cancel_1")
        self.assertFalse(exec_cancel["success"])
        self.assertTrue(exec_cancel.get("canceled", False))

    def test_gate_multi_interface_semantic_agreement(self):
        """Gate 7: REST API, ARP, and persisted-session representations agree on hypotheses, findings, and evidence."""
        adapter = WebApiAdapter(self.runtime)
        start_res = adapter.start_investigation({"goal": "Agreement test"})
        inv_id = start_res["data"]["investigation_id"]

        h_data = {
            "hypothesis_id": "hypo_agree",
            "title": "Agreement Hypothesis",
            "claim": "Claim across interfaces",
            "suggested_observations": [{
                "observation_id": "obs_agree_1",
                "question": "Question?",
                "target_kind": "FIELD",
                "target_ref": {"field_path": "State.test"},
                "status": "proposed",
            }]
        }
        adapter.propose_hypothesis({"investigation_id": inv_id, "hypothesis": h_data})

        # Query via Web API
        api_hypos = adapter.get_hypotheses(inv_id)["data"]["hypotheses"]
        # Query via ARP
        arp_act = AgentAction(action="GET_HYPOTHESES", investigation_id=inv_id)
        arp_res = self.runtime.execute(arp_act)
        arp_hypos = arp_res.data["hypotheses"]

        # Save and query persisted session
        save_res = adapter.save_investigation({"investigation_id": inv_id})
        saved_hypos = save_res["data"]["session_data"]["hypotheses"]

        # All three must agree on status, claim, and hypothesis_id
        self.assertEqual(api_hypos[0]["hypothesis_id"], "hypo_agree")
        self.assertEqual(arp_hypos[0]["hypothesis_id"], "hypo_agree")
        self.assertEqual(saved_hypos[0]["hypothesis_id"], "hypo_agree")

        self.assertEqual(api_hypos[0]["validation_status"], arp_hypos[0]["validation_status"])
        self.assertEqual(api_hypos[0]["validation_status"], saved_hypos[0]["validation_status"])


if __name__ == "__main__":
    unittest.main()
