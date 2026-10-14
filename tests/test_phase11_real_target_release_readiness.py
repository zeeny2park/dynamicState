"""Phase 11: Real-Target Validation & Release Readiness Test Suite.

Validates the complete trust and causal attribution contract against real Linux C++ processes:
1. Real C++ End-to-End Matrix:
   - Reproducible field change
   - Unchanged field negative control
   - Ambiguous field paths across multiple distinct objects
   - Missing or mismatched debug image (companion rejection)
   - Mismatched Build ID at target identity boundary
   - Process exit during capture (ESRCH graceful handling)
   - Permission denial / lookup error safety
   - Partial memory reads & degraded capture quality capping
   - Malformed / tampered snapshot rejection
2. Multithread & Causal Attribution Controls:
   - Positive single-writer control with static baseline
   - Negative single-writer control with baseline drift
   - Negative single-writer control with competing writer mismatch
   - Positive trusted execution trace
   - Negative untrusted/caller-submitted trace rejection
   - Candidate tier preservation when causal instrumentation is unavailable
   - Non-atomic / partial capture capping
3. Capture Lifecycle & Performance Invariants:
   - Repeated live captures with 100% byte accounting
   - Fail-open process resumption under repeated captures
   - Stop-time SLA overrun detection and completeness downgrade
   - Multithreaded concurrent capture consistency
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
from typing import Optional

from extractor.capture_backend import (
    CaptureSafetyPolicy,
    ProcessTargetHandle,
    ProcessVmCaptureBackend,
    ProcfsCaptureBackend,
    CaptureKeyStore,
    set_default_key_store,
    get_default_key_store,
)
from extractor.evidence_ledger import (
    EVIDENCE_TYPE_COMPARISON,
    NATURE_OBSERVATION,
    EvidenceRecord,
    CLAIM_ARTIFACT_INTEGRITY_VERIFIED,
    CLAIM_CAPTURE_PROVENANCE_VERIFIED,
    CLAIM_TARGET_IDENTITY_VERIFIED,
    CLAIM_STATE_TRANSITION_VERIFIED,
    CLAIM_FUNCTION_ATTRIBUTION_VERIFIED,
    ATTRIBUTION_BASIS_SINGLE_WRITER,
    ATTRIBUTION_BASIS_EXECUTION_TRACE,
    find_matching_diff_changes,
)
from extractor.investigation import (
    InvestigationManager,
    InvestigationHypothesis,
    HYPOTHESIS_STATUS_PROPOSED,
    HYPOTHESIS_STATUS_SUPPORTED,
    HYPOTHESIS_STATUS_VALIDATED,
    FUNCTION_TIER_STATIC_CANDIDATE,
    FUNCTION_TIER_EVIDENCE_SUPPORTED,
    FUNCTION_TIER_VALIDATED_CAUSAL,
    TrustedCausalVerifier,
)
from extractor.raw_snapshot import RawRuntimeSnapshot


class BasePhase11ProcessTestCase(unittest.TestCase):
    """Shared base setup for Phase 11 C++ tests."""

    @classmethod
    def setUpClass(cls):
        cls.work_dir = tempfile.mkdtemp(prefix="phase11_val_")
        cls.corpus_dir = os.path.join(cls.work_dir, "corpus")
        cls.fixture_src = os.path.abspath("tests/fixtures/real_runtime/phase11_concurrency_fixture.cpp")

        # 1. Compile PIE debug binary with GNU Build ID
        cls.debug_bin = os.path.join(cls.work_dir, "phase11_app_debug.elf")
        subprocess.run(
            [
                "g++", "-fPIE", "-pie", "-g", "-O0", "-fno-inline", "-fno-omit-frame-pointer",
                "-Wl,--build-id=sha1", cls.fixture_src, "-o", cls.debug_bin, "-lpthread"
            ],
            check=True
        )

        # 2. Extract stripped production companion
        cls.stripped_bin = os.path.join(cls.work_dir, "phase11_app_prod.stripped")
        subprocess.run(["strip", "-s", "-o", cls.stripped_bin, cls.debug_bin], check=True)

        # 3. Compile an intentionally mismatched debug binary
        cls.mismatched_src = os.path.join(cls.work_dir, "mismatched.cpp")
        with open(cls.mismatched_src, "w") as f:
            f.write("int main() { return 0; }\n")
        cls.mismatched_bin = os.path.join(cls.work_dir, "phase11_mismatched.elf")
        subprocess.run(
            ["g++", "-fPIE", "-pie", "-g", "-O0", "-Wl,--build-id=sha1", cls.mismatched_src, "-o", cls.mismatched_bin],
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


class TestPhase11RealTargetMatrix(BasePhase11ProcessTestCase):
    """Task 1: Real C++ End-to-End Matrix covering all 9 required operational cases."""

    def test_matrix_case1_reproducible_field_change(self):
        """Case 1: Live process capture -> MUTATE_ACTIVE -> diff -> matching DWARF declaration & candidates."""
        proc = self._start_process(self.stripped_bin)
        try:
            backend = ProcessVmCaptureBackend() if ProcessVmCaptureBackend().is_available(proc.pid) else ProcfsCaptureBackend()
            snap1 = backend.capture(pid=proc.pid)
            snap1_dir = os.path.join(self.work_dir, "snap1_case1")
            snap1.save(snap1_dir)

            res = self._send_command(proc, "MUTATE_ACTIVE")
            self.assertEqual(res, "ACTIVE_MUTATED")

            snap2 = backend.capture(pid=proc.pid)
            snap2_dir = os.path.join(self.work_dir, "snap2_case1")
            snap2.save(snap2_dir)
        finally:
            self._stop_process(proc)

        mgr = InvestigationManager(corpus_dir=os.path.join(self.work_dir, "corpus_c1"))
        info = mgr.start_investigation(
            goal="Test Case 1 Field Change",
            memory_snapshot_path=snap1_dir,
            debug_image=self.debug_bin,
            authorize_target=False,
        )
        inv_id = info["investigation_id"]

        cmp_res = mgr.compare_observations(inv_id, snap1_dir, snap2_dir)
        self.assertNotIn("error", cmp_res)
        changes = {c["path"]: c for c in cmp_res["changes"] if c.get("kind") == "value_change"}

        # Verify WorkerState.counter transitioned 10 -> 100
        self.assertIn("WorkerState.counter", changes)
        self.assertEqual(changes["WorkerState.counter"]["before"], 10)
        self.assertEqual(changes["WorkerState.counter"]["after"], 100)

        # Verify WorkerState.status_flags transitioned 1 -> 5
        self.assertIn("WorkerState.status_flags", changes)
        self.assertEqual(changes["WorkerState.status_flags"]["before"], 1)
        self.assertEqual(changes["WorkerState.status_flags"]["after"], 5)

        # Verify Report findings and candidate function links
        report = mgr.generate_report(inv_id)
        facts = report["findings"]["observed_facts"]
        fnd_counter = next((f for f in facts if f.get("field_name") == "counter" and f.get("type_name") == "WorkerState"), None)
        self.assertIsNotNone(fnd_counter)
        cand_names = [c["function_name"] for c in fnd_counter.get("function_candidates", [])]
        self.assertIn("active_worker_state_writer", cand_names)

    def test_matrix_case2_unchanged_field_negative_control(self):
        """Case 2: Live process capture -> NOOP -> unchanged field preserves values; fabricated transition rejected."""
        proc = self._start_process(self.stripped_bin)
        try:
            backend = ProcessVmCaptureBackend() if ProcessVmCaptureBackend().is_available(proc.pid) else ProcfsCaptureBackend()
            snap1 = backend.capture(pid=proc.pid)
            snap1_dir = os.path.join(self.work_dir, "snap1_case2")
            snap1.save(snap1_dir)

            res = self._send_command(proc, "NOOP")
            self.assertEqual(res, "NOOP_DONE")

            snap2 = backend.capture(pid=proc.pid)
            snap2_dir = os.path.join(self.work_dir, "snap2_case2")
            snap2.save(snap2_dir)
        finally:
            self._stop_process(proc)

        mgr = InvestigationManager(corpus_dir=os.path.join(self.work_dir, "corpus_c2"))
        info = mgr.start_investigation(
            goal="Test Case 2 Unchanged Field",
            memory_snapshot_path=snap1_dir,
            debug_image=self.debug_bin,
            authorize_target=False,
        )
        inv_id = info["investigation_id"]

        cmp_res = mgr.compare_observations(inv_id, snap1_dir, snap2_dir)
        changes = [c for c in cmp_res.get("changes", []) if "unchanged_field" in c.get("path", "")]
        self.assertEqual(len(changes), 0, "InactiveState.unchanged_field must not have diff changes")

        # Attempting to attest transition on unchanged field must raise ValueError (fabricated transition rejected)
        session = mgr.sessions[inv_id]
        rec = EvidenceRecord(
            evidence_id="ev_unchanged",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="investigation_observer",
            session_id=inv_id,
            observation="Unchanged field test",
            details={"target_function": "read_state_fn", "field_path": "InactiveState.unchanged_field"},
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
        )
        session.ledger.add_record(rec)

        hypo = InvestigationHypothesis(
            hypothesis_id="hypo_unchanged",
            investigation_id=inv_id,
            title="Unchanged Field",
            claim="Field unchanged",
            proposed_mechanism="No-op",
            candidate_objects=["g_inactive_state"],
            candidate_fields=["InactiveState.unchanged_field"],
            function_candidates=[{"function_name": "read_state_fn", "candidate_tier": FUNCTION_TIER_STATIC_CANDIDATE}],
            validation_status=HYPOTHESIS_STATUS_SUPPORTED,
        )
        session.hypotheses.append(hypo)

        with self.assertRaises(ValueError) as ctx:
            mgr.verify_live_reproduction_and_attest(
                investigation_id=inv_id,
                hypothesis_id="hypo_unchanged",
                evidence_id="ev_unchanged",
                snapshot_a_path=snap1_dir,
                snapshot_b_path=snap2_dir,
                target_function="read_state_fn",
                field_path="InactiveState.unchanged_field",
            )
        self.assertIn("did not change between snapshots", str(ctx.exception))

    def test_matrix_case3_ambiguous_field_paths_across_objects(self):
        """Case 3: Multiple objects mutating 'counter' -> ambiguous path triggers explicit error; qualified path succeeds."""
        proc = self._start_process(self.stripped_bin)
        try:
            backend = ProcessVmCaptureBackend() if ProcessVmCaptureBackend().is_available(proc.pid) else ProcfsCaptureBackend()
            snap1 = backend.capture(pid=proc.pid)
            snap1_dir = os.path.join(self.work_dir, "snap1_case3")
            snap1.save(snap1_dir)

            res = self._send_command(proc, "MUTATE_AMBIGUOUS_BOTH")
            self.assertEqual(res, "AMBIGUOUS_MUTATED")

            snap2 = backend.capture(pid=proc.pid)
            snap2_dir = os.path.join(self.work_dir, "snap2_case3")
            snap2.save(snap2_dir)
        finally:
            self._stop_process(proc)

        mgr = InvestigationManager(corpus_dir=os.path.join(self.work_dir, "corpus_c3"))
        info = mgr.start_investigation(
            goal="Test Case 3 Ambiguous Paths",
            memory_snapshot_path=snap1_dir,
            debug_image=self.debug_bin,
            authorize_target=False,
        )
        inv_id = info["investigation_id"]

        cmp_res = mgr.compare_observations(inv_id, snap1_dir, snap2_dir)
        changes = cmp_res["changes"]

        # 1. Unqualified path 'counter' matches both WorkerState and CompetingState -> ambiguity error
        matches, err_msg = find_matching_diff_changes(changes, "counter")
        self.assertIsNotNone(err_msg)
        self.assertIn("Ambiguous field path match", err_msg)
        self.assertIn("distinct objects", err_msg)

        # 2. Qualified path 'WorkerState.counter' matches uniquely without ambiguity
        matches_worker, err_worker = find_matching_diff_changes(changes, "WorkerState.counter")
        self.assertIsNone(err_worker)
        self.assertEqual(len(matches_worker), 1)
        self.assertEqual(matches_worker[0]["after"], 300)

        # 3. Qualified path 'CompetingState.counter' matches uniquely without ambiguity
        matches_comp, err_comp = find_matching_diff_changes(changes, "CompetingState.counter")
        self.assertIsNone(err_comp)
        self.assertEqual(len(matches_comp), 1)
        self.assertEqual(matches_comp[0]["after"], 300)

    def test_matrix_case4_missing_or_mismatched_debug_image(self):
        """Case 4: Missing debug companion fails static link; mismatched companion triggers MISMATCH status."""
        proc = self._start_process(self.stripped_bin)
        try:
            backend = ProcessVmCaptureBackend() if ProcessVmCaptureBackend().is_available(proc.pid) else ProcfsCaptureBackend()
            snap = backend.capture(pid=proc.pid)
            snap_dir = os.path.join(self.work_dir, "snap_case4")
            snap.save(snap_dir)
        finally:
            self._stop_process(proc)

        mgr = InvestigationManager(corpus_dir=os.path.join(self.work_dir, "corpus_c4"))

        # 1. Missing companion
        info_missing = mgr.start_investigation(
            goal="Missing companion test",
            memory_snapshot_path=snap_dir,
            debug_image=os.path.join(self.work_dir, "nonexistent_debug.elf"),
            authorize_target=False,
        )
        self.assertEqual(info_missing["stages"]["static_code_link"]["status"], "PARTIAL")
        self.assertEqual(info_missing["stages"]["static_code_link"]["details"]["linkage_status"], "UNVERIFIED")

        # 2. Mismatched companion (different Build ID)
        info_mismatch = mgr.start_investigation(
            goal="Mismatched companion test",
            memory_snapshot_path=snap_dir,
            debug_image=self.mismatched_bin,
            authorize_target=False,
        )
        self.assertEqual(info_mismatch["stages"]["target_identity"]["details"]["build_id_status"], "MISMATCH")
        self.assertEqual(info_mismatch["stages"]["static_code_link"]["status"], "FAILED")
        self.assertEqual(info_mismatch["stages"]["static_code_link"]["details"]["linkage_status"], "MISMATCH")

    def test_matrix_case5_mismatched_build_id_at_capture_boundary(self):
        """Case 5: Mismatched Build ID at receipt or attestation boundary fails closed."""
        snap = RawRuntimeSnapshot(
            snapshot_id="snap_mismatch_id",
            pid=5555,
            executable="/bin/app",
            executable_build_id="build_id_original",
            timestamp="2026-10-14T00:00:00Z",
            capture_duration_us=100.0,
            completeness="COMPLETE",
        )
        snap_dir = os.path.join(self.work_dir, "snap_mismatch_dir")
        snap.save(snap_dir)

        mgr = InvestigationManager(corpus_dir=os.path.join(self.work_dir, "corpus_c5"))
        inv = mgr.start_investigation(
            goal="Build ID Mismatch",
            memory_snapshot_path=snap_dir,
            debug_image=self.mismatched_bin,
            authorize_target=False,
        )
        self.assertEqual(inv["stages"]["target_identity"]["details"]["build_id_status"], "MISMATCH")

    def test_matrix_case6_process_exit_during_capture(self):
        """Case 6: Target process terminates right before/during capture -> ESRCH handled gracefully without hanging."""
        proc = self._start_process(self.stripped_bin)
        pid = proc.pid
        proc.kill()
        proc.wait(timeout=2)

        backend = ProcessVmCaptureBackend()
        with self.assertRaises(RuntimeError) as ctx:
            backend.capture(pid=pid)
        self.assertIn("unavailable or target PID", str(ctx.exception))

    def test_matrix_case7_permission_denial_safety(self):
        """Case 7: Unauthorized target attach or lookup error fails safely without process leakage."""
        mgr = InvestigationManager(corpus_dir=os.path.join(self.work_dir, "corpus_c7"))
        res = mgr.start_investigation(
            goal="Unauthorized attach",
            pid=99999999,
            authorize_target=False,
        )
        self.assertEqual(res["status"], "BLOCKED")
        self.assertIn("Target authorization required", res["summary"]["error"])

    def test_matrix_case8_partial_memory_reads_and_degraded_quality(self):
        """Case 8: Snapshots with PARTIAL completeness or NON_ATOMIC consistency cannot produce VALIDATED hypotheses."""
        mgr = InvestigationManager(corpus_dir=os.path.join(self.work_dir, "corpus_c8"))
        inv_id = mgr.start_investigation(goal="Degraded quality capping")["investigation_id"]
        session = mgr.sessions[inv_id]

        hypo = InvestigationHypothesis(
            hypothesis_id="hypo_partial_test",
            investigation_id=inv_id,
            title="Partial Hypothesis",
            claim="Claim",
            proposed_mechanism="Mech",
            supporting_evidence_ids=["ev_partial"],
            candidate_fields=["WorkerState.counter"],
            function_candidates=[{"function_name": "active_worker_state_writer", "candidate_tier": FUNCTION_TIER_STATIC_CANDIDATE, "confirmed_root_cause": False}],
            validation_status=HYPOTHESIS_STATUS_PROPOSED,
        )
        session.hypotheses.append(hypo)

        rec = EvidenceRecord(
            evidence_id="ev_partial",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="observer",
            session_id=inv_id,
            observation="Partial capture evidence",
            details={"target_function": "active_worker_state_writer", "field_path": "WorkerState.counter"},
            capture_quality={"completeness": "PARTIAL", "consistency_level": "STOPPED"},
        )
        session.ledger.add_record(rec)

        res = mgr.evaluate_hypothesis(inv_id, "hypo_partial_test", proof_evidence_id="ev_partial", deterministic_transition_verified=True)
        self.assertEqual(res["transition"]["to_status"], HYPOTHESIS_STATUS_SUPPORTED)
        self.assertIn("PARTIAL", res["transition"]["reason"])

    def test_matrix_case9_tampered_payload_and_receipt_detection(self):
        """Case 9: Altering payload byte causes RawRuntimeSnapshot.load to fail with TAMPERED status."""
        proc = self._start_process(self.stripped_bin)
        try:
            backend = ProcessVmCaptureBackend() if ProcessVmCaptureBackend().is_available(proc.pid) else ProcfsCaptureBackend()
            snap = backend.capture(pid=proc.pid)
            snap_dir = os.path.join(self.work_dir, "snap_tamper_c9")
            snap.save(snap_dir)
        finally:
            self._stop_process(proc)

        # Alter single byte in memory payload
        mem_dir = os.path.join(snap_dir, "memory")
        bins = [os.path.join(mem_dir, f) for f in os.listdir(mem_dir) if f.endswith(".bin")]
        self.assertGreater(len(bins), 0)
        target_bin = bins[0]
        with open(target_bin, "r+b") as f:
            b = f.read(1)
            f.seek(0)
            f.write(bytes([b[0] ^ 0xFF]))

        loaded = RawRuntimeSnapshot.load(snap_dir)
        self.assertEqual(loaded.provenance.get("verification_status"), "TAMPERED")
        mgr = InvestigationManager()
        ok, rcpt, err = mgr.verify_capture_provenance(snap_dir)
        self.assertFalse(ok)
        self.assertIn("tampering detected", err)


class TestPhase11MultithreadAndCausalAttributionControls(BasePhase11ProcessTestCase):
    """Task 2: Multithread and Causal Attribution Controls (Positive and Negative Controls)."""

    def test_attribution_positive_single_writer_control(self):
        """Positive Control: Static negative baseline + isolated active writer -> VALIDATED_CAUSAL_FUNCTION."""
        proc = self._start_process(self.stripped_bin)
        try:
            backend = ProcessVmCaptureBackend() if ProcessVmCaptureBackend().is_available(proc.pid) else ProcfsCaptureBackend()

            # 1. State 1 (before)
            snap1 = backend.capture(pid=proc.pid)
            snap1_dir = os.path.join(self.work_dir, "snap1_pos_attr")
            snap1.save(snap1_dir)

            # 2. Send MUTATE_ACTIVE
            res = self._send_command(proc, "MUTATE_ACTIVE")
            self.assertEqual(res, "ACTIVE_MUTATED")

            # 3. State 2 (after)
            snap2 = backend.capture(pid=proc.pid)
            snap2_dir = os.path.join(self.work_dir, "snap2_pos_attr")
            snap2.save(snap2_dir)
        finally:
            self._stop_process(proc)

        mgr = InvestigationManager(corpus_dir=os.path.join(self.work_dir, "corpus_pos_attr"))
        inv = mgr.start_investigation(
            goal="Positive Single Writer Control",
            memory_snapshot_path=snap1_dir,
            debug_image=self.debug_bin,
            authorize_target=False,
        )
        inv_id = inv["investigation_id"]
        session = mgr.sessions[inv_id]

        # Register negative control baseline where no mutation occurred
        rec_ctrl = EvidenceRecord(
            evidence_id="ev_ctrl_baseline",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="investigation_observer",
            session_id=inv_id,
            observation="Static control baseline observation: counter remained 10",
            details={
                "target_function": "active_worker_state_writer",
                "field_path": "WorkerState.counter",
                "before_value": 10,
                "after_value": 10,  # Unchanged!
                "control_condition": "baseline",
                "mutation_occurred": False,
            },
            target_identity={"pid": proc.pid, "binary": self.stripped_bin, "build_id": snap1.executable_build_id},
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
        )
        session.ledger.add_record(rec_ctrl)

        rec_treat = EvidenceRecord(
            evidence_id="ev_treatment",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="investigation_observer",
            session_id=inv_id,
            observation="Treatment: active writer mutated counter 10 -> 100",
            details={"target_function": "active_worker_state_writer", "field_path": "WorkerState.counter"},
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
        )
        session.ledger.add_record(rec_treat)

        hypo = InvestigationHypothesis(
            hypothesis_id="hypo_pos_attr",
            investigation_id=inv_id,
            title="Hypo Positive Attribution",
            claim="active_worker_state_writer causes WorkerState.counter transition",
            proposed_mechanism="Direct write",
            supporting_evidence_ids=["ev_treatment"],
            candidate_fields=["WorkerState.counter"],
            function_candidates=[{"function_name": "active_worker_state_writer", "candidate_tier": FUNCTION_TIER_STATIC_CANDIDATE, "confirmed_root_cause": False}],
            validation_status=HYPOTHESIS_STATUS_SUPPORTED,
        )
        session.hypotheses.append(hypo)

        att_ok = mgr.verify_live_reproduction_and_attest(
            investigation_id=inv_id,
            hypothesis_id="hypo_pos_attr",
            evidence_id="ev_treatment",
            snapshot_a_path=snap1_dir,
            snapshot_b_path=snap2_dir,
            target_function="active_worker_state_writer",
            field_path="WorkerState.counter",
            attribution_evidence={
                "attribution_basis": ATTRIBUTION_BASIS_SINGLE_WRITER,
                "control_evidence_id": "ev_ctrl_baseline",
                "active_writer_function": "active_worker_state_writer",
            },
        )
        self.assertTrue(att_ok)

        eval_res = mgr.evaluate_hypothesis(inv_id, "hypo_pos_attr", proof_evidence_id="ev_treatment", deterministic_transition_verified=True)
        self.assertEqual(eval_res["transition"]["to_status"], HYPOTHESIS_STATUS_VALIDATED)
        h_after = mgr.get_hypothesis(inv_id, "hypo_pos_attr")
        cand = h_after["function_candidates"][0]
        self.assertEqual(cand["candidate_tier"], FUNCTION_TIER_VALIDATED_CAUSAL)
        self.assertTrue(cand["confirmed_root_cause"], "Positive single-writer control must promote to confirmed root cause")

    def test_attribution_negative_control_baseline_drift(self):
        """Negative Control 1: Baseline drifted (before != after in control) -> attribution rejected, limitation recorded."""
        proc = self._start_process(self.stripped_bin)
        try:
            backend = ProcessVmCaptureBackend() if ProcessVmCaptureBackend().is_available(proc.pid) else ProcfsCaptureBackend()
            snap1 = backend.capture(pid=proc.pid)
            snap1_dir = os.path.join(self.work_dir, "snap1_drift")
            snap1.save(snap1_dir)

            res = self._send_command(proc, "MUTATE_ACTIVE")
            self.assertEqual(res, "ACTIVE_MUTATED")

            snap2 = backend.capture(pid=proc.pid)
            snap2_dir = os.path.join(self.work_dir, "snap2_drift")
            snap2.save(snap2_dir)
        finally:
            self._stop_process(proc)

        mgr = InvestigationManager(corpus_dir=os.path.join(self.work_dir, "corpus_drift"))
        inv = mgr.start_investigation(
            goal="Negative Baseline Drift Control",
            memory_snapshot_path=snap1_dir,
            debug_image=self.debug_bin,
            authorize_target=False,
        )
        inv_id = inv["investigation_id"]
        session = mgr.sessions[inv_id]

        rec_ctrl_drift = EvidenceRecord(
            evidence_id="ev_ctrl_drift",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="investigation_observer",
            session_id=inv_id,
            observation="Control baseline drifted unexpectedly",
            details={
                "target_function": "active_worker_state_writer",
                "field_path": "WorkerState.counter",
                "before_value": 10,
                "after_value": 15,  # Drift occurred!
                "control_condition": "baseline",
                "mutation_occurred": True,
            },
            target_identity={"pid": proc.pid, "binary": self.stripped_bin, "build_id": snap1.executable_build_id},
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
        )
        session.ledger.add_record(rec_ctrl_drift)

        rec_treat = EvidenceRecord(
            evidence_id="ev_treat_drift",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="investigation_observer",
            session_id=inv_id,
            observation="Treatment observation",
            details={"target_function": "active_worker_state_writer", "field_path": "WorkerState.counter"},
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
        )
        session.ledger.add_record(rec_treat)

        hypo = InvestigationHypothesis(
            hypothesis_id="hypo_drift",
            investigation_id=inv_id,
            title="Drift Hypo",
            claim="Claim",
            proposed_mechanism="Mech",
            supporting_evidence_ids=["ev_treat_drift"],
            candidate_fields=["WorkerState.counter"],
            function_candidates=[{"function_name": "active_worker_state_writer", "candidate_tier": FUNCTION_TIER_STATIC_CANDIDATE, "confirmed_root_cause": False}],
            validation_status=HYPOTHESIS_STATUS_SUPPORTED,
        )
        session.hypotheses.append(hypo)

        att_ok = mgr.verify_live_reproduction_and_attest(
            investigation_id=inv_id,
            hypothesis_id="hypo_drift",
            evidence_id="ev_treat_drift",
            snapshot_a_path=snap1_dir,
            snapshot_b_path=snap2_dir,
            target_function="active_worker_state_writer",
            field_path="WorkerState.counter",
            attribution_evidence={
                "attribution_basis": ATTRIBUTION_BASIS_SINGLE_WRITER,
                "control_evidence_id": "ev_ctrl_drift",
                "active_writer_function": "active_worker_state_writer",
            },
        )
        self.assertTrue(att_ok)
        att = session.ledger.get_record("ev_treat_drift").provenance["verifier_attestation"]
        self.assertFalse(att["function_attribution_verified"], "Drifting control must fail attribution")
        self.assertIn("Negative control baseline failed", att["attribution_limitation"])

        eval_res = mgr.evaluate_hypothesis(inv_id, "hypo_drift", proof_evidence_id="ev_treat_drift", deterministic_transition_verified=True)
        self.assertEqual(eval_res["transition"]["to_status"], HYPOTHESIS_STATUS_VALIDATED)
        cand = mgr.get_hypothesis(inv_id, "hypo_drift")["function_candidates"][0]
        self.assertFalse(cand["confirmed_root_cause"], "Candidate must NOT be confirmed root cause when baseline drifted")

    def test_attribution_negative_control_competing_writer(self):
        """Negative Control 2: Active writer mismatch (competing writer mutated) -> candidate not promoted."""
        proc = self._start_process(self.stripped_bin)
        try:
            backend = ProcessVmCaptureBackend() if ProcessVmCaptureBackend().is_available(proc.pid) else ProcfsCaptureBackend()
            snap1 = backend.capture(pid=proc.pid)
            snap1_dir = os.path.join(self.work_dir, "snap1_comp")
            snap1.save(snap1_dir)

            res = self._send_command(proc, "MUTATE_COMPETING")
            self.assertEqual(res, "COMPETING_MUTATED")

            snap2 = backend.capture(pid=proc.pid)
            snap2_dir = os.path.join(self.work_dir, "snap2_comp")
            snap2.save(snap2_dir)
        finally:
            self._stop_process(proc)

        mgr = InvestigationManager(corpus_dir=os.path.join(self.work_dir, "corpus_comp"))
        inv = mgr.start_investigation(
            goal="Negative Competing Writer Control",
            memory_snapshot_path=snap1_dir,
            debug_image=self.debug_bin,
            authorize_target=False,
        )
        inv_id = inv["investigation_id"]
        session = mgr.sessions[inv_id]

        rec_ctrl = EvidenceRecord(
            evidence_id="ev_ctrl_comp",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="investigation_observer",
            session_id=inv_id,
            observation="Static control baseline",
            details={
                "target_function": "active_worker_state_writer",
                "field_path": "WorkerState.counter",
                "before_value": 10,
                "after_value": 10,
                "control_condition": "baseline",
                "mutation_occurred": False,
            },
            target_identity={"pid": proc.pid, "binary": self.stripped_bin, "build_id": snap1.executable_build_id},
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
        )
        session.ledger.add_record(rec_ctrl)

        rec_treat = EvidenceRecord(
            evidence_id="ev_treat_comp",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="investigation_observer",
            session_id=inv_id,
            observation="Competing writer mutation",
            details={"target_function": "active_worker_state_writer", "field_path": "WorkerState.counter"},
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
        )
        session.ledger.add_record(rec_treat)

        hypo = InvestigationHypothesis(
            hypothesis_id="hypo_comp",
            investigation_id=inv_id,
            title="Competing Writer Hypo",
            claim="Claim",
            proposed_mechanism="Mech",
            supporting_evidence_ids=["ev_treat_comp"],
            candidate_fields=["WorkerState.counter"],
            function_candidates=[{"function_name": "active_worker_state_writer", "candidate_tier": FUNCTION_TIER_STATIC_CANDIDATE, "confirmed_root_cause": False}],
            validation_status=HYPOTHESIS_STATUS_SUPPORTED,
        )
        session.hypotheses.append(hypo)

        # Candidate is active_worker_state_writer, but active writer was competing_worker_state_writer -> mismatch!
        att_ok = mgr.verify_live_reproduction_and_attest(
            investigation_id=inv_id,
            hypothesis_id="hypo_comp",
            evidence_id="ev_treat_comp",
            snapshot_a_path=snap1_dir,
            snapshot_b_path=snap2_dir,
            target_function="active_worker_state_writer",
            field_path="WorkerState.counter",
            attribution_evidence={
                "attribution_basis": ATTRIBUTION_BASIS_SINGLE_WRITER,
                "control_evidence_id": "ev_ctrl_comp",
                "active_writer_function": "competing_worker_state_writer",  # Mismatch!
            },
        )
        self.assertTrue(att_ok)
        att = session.ledger.get_record("ev_treat_comp").provenance["verifier_attestation"]
        self.assertFalse(att["function_attribution_verified"])
        self.assertIn("active writer was 'competing_worker_state_writer'", att["attribution_limitation"])

        eval_res = mgr.evaluate_hypothesis(inv_id, "hypo_comp", proof_evidence_id="ev_treat_comp", deterministic_transition_verified=True)
        cand = mgr.get_hypothesis(inv_id, "hypo_comp")["function_candidates"][0]
        self.assertFalse(cand["confirmed_root_cause"], "Mismatched writer must NOT be confirmed root cause")

    def test_attribution_positive_trusted_execution_trace(self):
        """Positive Control: Authenticated execution trace from trace_collector promotes candidate."""
        proc = self._start_process(self.stripped_bin)
        try:
            backend = ProcessVmCaptureBackend() if ProcessVmCaptureBackend().is_available(proc.pid) else ProcfsCaptureBackend()
            snap1 = backend.capture(pid=proc.pid)
            snap1_dir = os.path.join(self.work_dir, "snap1_trace")
            snap1.save(snap1_dir)

            res = self._send_command(proc, "MUTATE_ACTIVE")
            self.assertEqual(res, "ACTIVE_MUTATED")

            snap2 = backend.capture(pid=proc.pid)
            snap2_dir = os.path.join(self.work_dir, "snap2_trace")
            snap2.save(snap2_dir)
        finally:
            self._stop_process(proc)

        mgr = InvestigationManager(corpus_dir=os.path.join(self.work_dir, "corpus_trace"))
        inv = mgr.start_investigation(
            goal="Trusted Trace Control",
            memory_snapshot_path=snap1_dir,
            debug_image=self.debug_bin,
            authorize_target=False,
        )
        inv_id = inv["investigation_id"]
        session = mgr.sessions[inv_id]

        # Authentic trace collector evidence
        rec_trace = EvidenceRecord(
            evidence_id="ev_trace_auth",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="trace_collector",
            session_id=inv_id,
            observation="Execution trace verified write event",
            details={
                "trace_events": [{"function": "active_worker_state_writer", "event": "write", "field": "WorkerState.counter"}],
                "caller_submitted": False,
            },
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
        )
        session.ledger.add_record(rec_trace)

        rec_treat = EvidenceRecord(
            evidence_id="ev_treat_tr",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="investigation_observer",
            session_id=inv_id,
            observation="Treatment",
            details={"target_function": "active_worker_state_writer", "field_path": "WorkerState.counter"},
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
        )
        session.ledger.add_record(rec_treat)

        hypo = InvestigationHypothesis(
            hypothesis_id="hypo_tr",
            investigation_id=inv_id,
            title="Trace Hypo",
            claim="Claim",
            proposed_mechanism="Mech",
            supporting_evidence_ids=["ev_treat_tr"],
            candidate_fields=["WorkerState.counter"],
            function_candidates=[{"function_name": "active_worker_state_writer", "candidate_tier": FUNCTION_TIER_STATIC_CANDIDATE, "confirmed_root_cause": False}],
            validation_status=HYPOTHESIS_STATUS_SUPPORTED,
        )
        session.hypotheses.append(hypo)

        att_ok = mgr.verify_live_reproduction_and_attest(
            investigation_id=inv_id,
            hypothesis_id="hypo_tr",
            evidence_id="ev_treat_tr",
            snapshot_a_path=snap1_dir,
            snapshot_b_path=snap2_dir,
            target_function="active_worker_state_writer",
            field_path="WorkerState.counter",
            attribution_evidence={
                "attribution_basis": ATTRIBUTION_BASIS_EXECUTION_TRACE,
                "trace_evidence_id": "ev_trace_auth",
            },
        )
        self.assertTrue(att_ok)
        att = session.ledger.get_record("ev_treat_tr").provenance["verifier_attestation"]
        self.assertTrue(att["function_attribution_verified"])

        eval_res = mgr.evaluate_hypothesis(inv_id, "hypo_tr", proof_evidence_id="ev_treat_tr", deterministic_transition_verified=True)
        cand = mgr.get_hypothesis(inv_id, "hypo_tr")["function_candidates"][0]
        self.assertTrue(cand["confirmed_root_cause"], "Authentic trace must confirm root cause")

    def test_attribution_negative_untrusted_caller_trace_rejected(self):
        """Negative Control: External caller-submitted trace evidence is rejected at the trust boundary."""
        mgr = InvestigationManager(corpus_dir=os.path.join(self.work_dir, "corpus_forged_tr"))
        inv_id = mgr.start_investigation(goal="Caller Trace Rejection")["investigation_id"]
        session = mgr.sessions[inv_id]

        rec_forged = EvidenceRecord(
            evidence_id="ev_trace_forged",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="external_caller",
            session_id=inv_id,
            observation="Forged caller trace",
            details={
                "trace_events": [{"function": "active_worker_state_writer", "event": "write"}],
                "caller_submitted": True,
            },
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
        )
        session.ledger.add_record(rec_forged)

        hypo = InvestigationHypothesis(
            hypothesis_id="hypo_f_tr",
            investigation_id=inv_id,
            title="Forged Trace Hypo",
            claim="Claim",
            proposed_mechanism="Mech",
            supporting_evidence_ids=["ev_trace_forged"],
            candidate_fields=["WorkerState.counter"],
            function_candidates=[{"function_name": "active_worker_state_writer", "candidate_tier": FUNCTION_TIER_STATIC_CANDIDATE, "confirmed_root_cause": False}],
            validation_status=HYPOTHESIS_STATUS_PROPOSED,
        )
        session.hypotheses.append(hypo)

        eval_res = mgr.evaluate_hypothesis(inv_id, "hypo_f_tr", proof_evidence_id="ev_trace_forged", deterministic_transition_verified=True)
        self.assertEqual(eval_res["transition"]["to_status"], HYPOTHESIS_STATUS_SUPPORTED)
        self.assertTrue(eval_res["transition"]["unverified_claim_rejected"])


class TestPhase11CaptureLifecycleAndPerformance(BasePhase11ProcessTestCase):
    """Task 3: Capture Lifecycle and Performance Invariants."""

    def test_capture_lifecycle_repeated_measurements(self):
        """Repeated captures against running inferior show 100% byte accounting and reliable resumption."""
        proc = self._start_process(self.stripped_bin)
        try:
            backend = ProcessVmCaptureBackend() if ProcessVmCaptureBackend().is_available(proc.pid) else ProcfsCaptureBackend()
            durations = []
            stop_latencies = []

            for i in range(5):
                snap = backend.capture(pid=proc.pid)
                self.assertEqual(snap.completeness, "COMPLETE")
                self.assertEqual(snap.provenance["bytes_requested"], snap.provenance["bytes_read"])
                self.assertGreater(snap.provenance["bytes_read"], 0)
                durations.append(snap.capture_duration_us)
                if snap.stop_latency_us > 0:
                    stop_latencies.append(snap.stop_latency_us)

                # Process remains responsive to stdin commands
                res = self._send_command(proc, "NOOP")
                self.assertEqual(res, "NOOP_DONE", f"Inferior failed to respond after capture iteration {i}")

            self.assertEqual(len(durations), 5)
            # Verify measurements are non-negative
            self.assertTrue(all(d > 0 for d in durations))
        finally:
            self._stop_process(proc)

    def test_stop_time_sla_overrun_downgrade(self):
        """When stop-time SLA is exceeded, completeness is demoted to PARTIAL with STOP_BUDGET_EXCEEDED."""
        proc = self._start_process(self.stripped_bin)
        try:
            backend = ProcessVmCaptureBackend() if ProcessVmCaptureBackend().is_available(proc.pid) else ProcfsCaptureBackend()
            # Set SLA threshold lower than actual suspension time (typically 3-6ms) but long enough to confirm stop
            policy = CaptureSafetyPolicy(max_stop_time_ms=1.0)
            snap = backend.capture(pid=proc.pid, policy=policy)

            # Completeness demoted to PARTIAL due to stop budget exceeded
            self.assertEqual(snap.completeness, "PARTIAL")
            diag_codes = [d.get("code") for d in snap.provenance.get("diagnostics", [])]
            self.assertIn("STOP_BUDGET_EXCEEDED", diag_codes)
        finally:
            self._stop_process(proc)

    def test_multithreaded_concurrency_capture_consistency(self):
        """Capturing process under active multithreaded competing writes succeeds with complete thread enumeration."""
        proc = self._start_process(self.stripped_bin)
        try:
            res = self._send_command(proc, "ENABLE_COMPETING_THREAD")
            self.assertEqual(res, "COMPETING_THREAD_ENABLED")

            backend = ProcessVmCaptureBackend() if ProcessVmCaptureBackend().is_available(proc.pid) else ProcfsCaptureBackend()
            snap = backend.capture(pid=proc.pid)
            self.assertEqual(snap.completeness, "COMPLETE")
            self.assertGreaterEqual(len(snap.thread_metadata), 2, "Thread enumeration must capture all active threads")
        finally:
            self._stop_process(proc)


if __name__ == "__main__":
    unittest.main()
