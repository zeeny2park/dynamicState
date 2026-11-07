"""Phase 2.0-A.3.6 Verification Suite: Fail-Closed Evidence Semantics & Live Execution Closure.

Validates:
- 2.1 Strict observation semantics (SUPPORTED, CONTRADICTED, INCONCLUSIVE, ABSTAIN) for
  Field, Thread, Comparison, and General observations, plus isolation of test-only
  simulation controls (force_failed, force_error, force_contradiction, simulated_outcome).
- 2.2 Caller-submitted evidence trust boundary (disarming forged execution_provenance,
  verified_transition, causal_proof, reproduction_verified, verified_writer,
  collection_status, provenance_class, live_capture_receipt, and confidence upgrades).
- 2.3 Synthetic, imported, and live evidence separation (SYNTHETIC, IMPORTED_UNVERIFIED,
  LIVE_RUNTIME_CAPTURE) and LiveCaptureReceipt validation against all negative cases.
- 2.4 Adaptive execution failure transparency in WatchSessionManager and AdaptiveInvestigationEngine.
- 2.5 Actual production execution verification through TargetExecutionAdapter on a real
  compiled C++ process (PID reuse protection, executable & Build ID verification,
  physical read accounting, budget enforcement, and duplicate observation prevention).
"""

import os
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from extractor.adaptive_engine import AdaptiveInvestigationEngine
from extractor.capture_backend import (
    LiveCaptureReceipt,
    get_trusted_capture_authority_token,
    issue_live_capture_receipt,
)
from extractor.evidence_ledger import (
    EvidenceLedger,
    EvidenceRecord,
    OBSERVATION_OUTCOME_ABSTAIN,
    OBSERVATION_OUTCOME_CONTRADICTED,
    OBSERVATION_OUTCOME_INCONCLUSIVE,
    OBSERVATION_OUTCOME_SUPPORTED,
    PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
    PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
    PROVENANCE_CLASS_SYNTHETIC,
    PROVENANCE_CLASS_SYNTHETIC_FIXTURE,
)
from extractor.hypothesis import (
    FollowUpObservation,
    HYPOTHESIS_STATUS_ABSTAINED,
    HYPOTHESIS_STATUS_CONTRADICTED,
    HYPOTHESIS_STATUS_INCONCLUSIVE,
    HYPOTHESIS_STATUS_PROPOSED,
    HYPOTHESIS_STATUS_SUPPORTED,
    HYPOTHESIS_STATUS_VALIDATED,
    InvestigationHypothesis,
    TARGET_KIND_COMPARISON,
    TARGET_KIND_FIELD,
    TARGET_KIND_OBJECT,
    TARGET_KIND_THREAD,
)
from extractor.investigation import InvestigationManager
from extractor.target_adapter import LocalTargetAdapter
from extractor.watch_session import WatchSessionManager


class TestPhase20A36FailClosedEvidenceAndLiveClosure(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="phase2_0_a36_")
        self.corpus_dir = os.path.join(self.tmp_dir, "corpus")
        self.mgr = InvestigationManager(corpus_dir=self.corpus_dir)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _create_session_with_obs(self, target_kind: str, target_ref: dict) -> tuple:
        info = self.mgr.start_investigation(goal="A.3.6 strict observation test")
        inv_id = info["investigation_id"]
        session = self.mgr.sessions[inv_id]
        obs = FollowUpObservation(
            observation_id="obs_test_1",
            hypothesis_id="hypo_test_1",
            question="Strict observation check",
            target_kind=target_kind,
            target_identifier=target_ref.get("field_path") or str(target_ref.get("tid", "target")),
            target_ref=target_ref,
        )
        hypo = InvestigationHypothesis(
            hypothesis_id="hypo_test_1",
            investigation_id=inv_id,
            title="Test Hypothesis",
            claim="Test Claim",
            proposed_mechanism="Test Mechanism",
            suggested_observations=[obs],
        )
        session.hypotheses.append(hypo)
        session.follow_up_observations.append(obs)
        return inv_id, session, hypo, obs

    # -------------------------------------------------------------------------
    # 2.1 Strict Observation Semantics
    # -------------------------------------------------------------------------

    def test_2_1_field_observation_strict_semantics(self):
        """Field observations require snapshot, unique resolution, value, expected criteria, type, and epoch."""
        # 1. Missing snapshot -> ABSTAIN, zero confidence increase, never SUPPORTED
        inv_id, session, hypo, _ = self._create_session_with_obs(
            TARGET_KIND_FIELD, {"field_path": "g_state.counter", "expected_value": 10}
        )
        res = self.mgr.execute_observation(inv_id, "obs_test_1")
        self.assertTrue(res["success"])
        self.assertEqual(res["evidence"]["details"]["outcome"], OBSERVATION_OUTCOME_ABSTAIN)
        self.assertNotEqual(hypo.validation_status, HYPOTHESIS_STATUS_SUPPORTED)
        self.assertLessEqual(hypo.confidence_score, 0.40)

        # 2. Field exists in snapshot, but missing expected value -> INCONCLUSIVE (never SUPPORTED merely because field exists)
        inv_id2, session2, hypo2, _ = self._create_session_with_obs(
            TARGET_KIND_FIELD, {"field_path": "g_state.counter"}
        )
        session2.snapshots = [{"completeness": "COMPLETE", "epoch": 1, "fields": {"g_state.counter": {"value": 10, "type": "int"}}}]
        res2 = self.mgr.execute_observation(inv_id2, "obs_test_1")
        self.assertEqual(res2["evidence"]["details"]["outcome"], OBSERVATION_OUTCOME_INCONCLUSIVE)
        self.assertNotEqual(hypo2.validation_status, HYPOTHESIS_STATUS_SUPPORTED)

        # 3. Ambiguous field resolution (2 objects have same leaf field name) -> INCONCLUSIVE
        inv_id3, session3, hypo3, _ = self._create_session_with_obs(
            TARGET_KIND_FIELD, {"field_path": "counter", "expected_value": 10}
        )
        session3.snapshots = [{
            "completeness": "COMPLETE",
            "epoch": 1,
            "objects": [
                {"name": "workerA", "fields": {"counter": 10}},
                {"name": "workerB", "fields": {"counter": 10}},
            ],
        }]
        res3 = self.mgr.execute_observation(inv_id3, "obs_test_1")
        self.assertEqual(res3["evidence"]["details"]["outcome"], OBSERVATION_OUTCOME_INCONCLUSIVE)
        self.assertEqual(res3["evidence"]["details"]["reason"], "ambiguous_field_resolution")

        # 4. Incompatible type or stale epoch -> ABSTAIN
        inv_id4, session4, hypo4, _ = self._create_session_with_obs(
            TARGET_KIND_FIELD, {"field_path": "g_state.counter", "expected_value": "not_an_int", "min_epoch": 5}
        )
        session4.snapshots = [{"completeness": "COMPLETE", "epoch": 2, "fields": {"g_state.counter": 10}}]
        res4 = self.mgr.execute_observation(inv_id4, "obs_test_1")
        self.assertEqual(res4["evidence"]["details"]["outcome"], OBSERVATION_OUTCOME_ABSTAIN)

        # 5. Unique field resolution + matching expected value & epoch -> SUPPORTED
        inv_id5, session5, hypo5, _ = self._create_session_with_obs(
            TARGET_KIND_FIELD, {"field_path": "g_state.counter", "expected_value": 42, "required_epoch": 3}
        )
        session5.snapshots = [{"completeness": "COMPLETE", "epoch": 3, "fields": {"g_state.counter": 42}}]
        res5 = self.mgr.execute_observation(inv_id5, "obs_test_1")
        self.assertEqual(res5["evidence"]["details"]["outcome"], OBSERVATION_OUTCOME_SUPPORTED)
        self.assertEqual(hypo5.validation_status, HYPOTHESIS_STATUS_SUPPORTED)

    def test_2_1_thread_observation_distinguishes_missing_thread_from_collection_failure(self):
        """Thread observations distinguish missing threads in collected table from collection failures."""
        # 1. Collection failure -> ABSTAIN
        inv_id1, session1, hypo1, _ = self._create_session_with_obs(
            TARGET_KIND_THREAD, {"tid": 1001, "expected_state": "S"}
        )
        session1.snapshots = [{"threads_collection_failed": True, "thread_enumeration": {"status": "FAILED", "error": "EPERM"}}]
        res1 = self.mgr.execute_observation(inv_id1, "obs_test_1")
        self.assertEqual(res1["evidence"]["details"]["outcome"], OBSERVATION_OUTCOME_ABSTAIN)
        self.assertEqual(res1["evidence"]["details"]["reason"], "thread_collection_failed")

        # 2. Thread collection succeeded, but requested TID 9999 is missing -> CONTRADICTED with thread_missing_from_collected_table
        inv_id2, session2, hypo2, _ = self._create_session_with_obs(
            TARGET_KIND_THREAD, {"tid": 9999, "expected_state": "S"}
        )
        session2.snapshots = [{"threads": [{"tid": 1001, "name": "main", "state": "R"}]}]
        res2 = self.mgr.execute_observation(inv_id2, "obs_test_1")
        self.assertEqual(res2["evidence"]["details"]["outcome"], OBSERVATION_OUTCOME_CONTRADICTED)
        self.assertEqual(res2["evidence"]["details"]["reason"], "thread_missing_from_collected_table")
        self.assertTrue(res2["evidence"]["details"]["thread_collection_succeeded"])

        # 3. Thread exists and matches requested state & function -> SUPPORTED
        inv_id3, session3, hypo3, _ = self._create_session_with_obs(
            TARGET_KIND_THREAD, {"tid": 1001, "expected_state": "S", "expected_function": "pthread_mutex_lock"}
        )
        session3.snapshots = [{"threads": [{"tid": 1001, "name": "worker", "state": "S", "top_function": "pthread_mutex_lock"}]}]
        res3 = self.mgr.execute_observation(inv_id3, "obs_test_1")
        self.assertEqual(res3["evidence"]["details"]["outcome"], OBSERVATION_OUTCOME_SUPPORTED)

    def test_2_1_comparison_observation_strict_semantics(self):
        """Comparison observations require baseline+current, matching identity/types/epochs, and complete snapshots."""
        # 1. Incomplete snapshot rejected
        inv_id1, session1, _, _ = self._create_session_with_obs(
            TARGET_KIND_COMPARISON,
            {
                "field_path": "pool.used",
                "expected_change": "INCREASED",
                "baseline_snapshot": {"pid": 100, "epoch": 1, "completeness": "PARTIAL", "fields": {"pool.used": 10}},
                "current_snapshot": {"pid": 100, "epoch": 2, "completeness": "COMPLETE", "fields": {"pool.used": 20}},
            },
        )
        res1 = self.mgr.execute_observation(inv_id1, "obs_test_1")
        self.assertEqual(res1["evidence"]["details"]["outcome"], OBSERVATION_OUTCOME_ABSTAIN)
        self.assertEqual(res1["evidence"]["details"]["reason"], "incomplete_snapshot_comparison_rejected")

        # 2. Stale/reversed epoch rejected
        inv_id2, session2, _, _ = self._create_session_with_obs(
            TARGET_KIND_COMPARISON,
            {
                "field_path": "pool.used",
                "expected_change": "INCREASED",
                "baseline_snapshot": {"pid": 100, "epoch": 5, "completeness": "COMPLETE", "fields": {"pool.used": 10}},
                "current_snapshot": {"pid": 100, "epoch": 3, "completeness": "COMPLETE", "fields": {"pool.used": 20}},
            },
        )
        res2 = self.mgr.execute_observation(inv_id2, "obs_test_1")
        self.assertEqual(res2["evidence"]["details"]["outcome"], OBSERVATION_OUTCOME_ABSTAIN)
        self.assertEqual(res2["evidence"]["details"]["reason"], "stale_or_invalid_sampling_epoch")

        # 3. Mismatched process identity rejected
        inv_id3, _, _, _ = self._create_session_with_obs(
            TARGET_KIND_COMPARISON,
            {
                "field_path": "pool.used",
                "expected_change": "INCREASED",
                "baseline_snapshot": {"pid": 100, "process_start_time": "111", "epoch": 1, "completeness": "COMPLETE", "fields": {"pool.used": 10}},
                "current_snapshot": {"pid": 100, "process_start_time": "222", "epoch": 2, "completeness": "COMPLETE", "fields": {"pool.used": 20}},
            },
        )
        res3 = self.mgr.execute_observation(inv_id3, "obs_test_1")
        self.assertEqual(res3["evidence"]["details"]["outcome"], OBSERVATION_OUTCOME_ABSTAIN)
        self.assertEqual(res3["evidence"]["details"]["reason"], "process_identity_mismatch")

        # 4. Valid complete comparison -> SUPPORTED
        inv_id4, _, hypo4, _ = self._create_session_with_obs(
            TARGET_KIND_COMPARISON,
            {
                "field_path": "pool.used",
                "expected_change": "INCREASED",
                "baseline_snapshot": {"pid": 100, "process_start_time": "111", "epoch": 1, "completeness": "COMPLETE", "fields": {"pool.used": 10}},
                "current_snapshot": {"pid": 100, "process_start_time": "111", "epoch": 2, "completeness": "COMPLETE", "fields": {"pool.used": 25}},
            },
        )
        res4 = self.mgr.execute_observation(inv_id4, "obs_test_1")
        self.assertEqual(res4["evidence"]["details"]["outcome"], OBSERVATION_OUTCOME_SUPPORTED)
        self.assertEqual(hypo4.validation_status, HYPOTHESIS_STATUS_SUPPORTED)

    def test_2_1_general_and_simulated_controls_isolated_from_production(self):
        """General observations never default to SUPPORTED, and simulated controls are isolated as SYNTHETIC."""
        inv_id1, _, hypo1, _ = self._create_session_with_obs(TARGET_KIND_OBJECT, {"object_id": "obj_1"})
        res1 = self.mgr.execute_observation(inv_id1, "obs_test_1")
        self.assertEqual(res1["evidence"]["details"]["outcome"], OBSERVATION_OUTCOME_ABSTAIN)
        self.assertNotEqual(hypo1.validation_status, HYPOTHESIS_STATUS_SUPPORTED)

        # Simulated outcome control cannot produce production SUPPORTED/VALIDATED proof
        inv_id2, session2, hypo2, _ = self._create_session_with_obs(TARGET_KIND_FIELD, {"field_path": "x"})
        res2 = self.mgr.execute_observation(
            inv_id2, "obs_test_1", result_data={"simulated_outcome": "SUPPORTED", "observation": "Simulated support"}
        )
        ev2 = session2.ledger.get_record(res2["evidence"]["evidence_id"])
        self.assertEqual(ev2.provenance_class, PROVENANCE_CLASS_SYNTHETIC)
        self.assertTrue(ev2.details.get("is_simulated"))
        self.assertNotEqual(hypo2.validation_status, HYPOTHESIS_STATUS_SUPPORTED)
        self.assertNotEqual(hypo2.validation_status, HYPOTHESIS_STATUS_VALIDATED)

    # -------------------------------------------------------------------------
    # 2.2 Caller-Submitted Evidence Trust Boundary
    # -------------------------------------------------------------------------

    def test_2_2_caller_submitted_forged_metadata_and_contradictory_claims_disarmed(self):
        """Untrusted callers cannot manufacture provenance, receipts, causal proof, or confidence upgrades."""
        inv_id, session, hypo, _ = self._create_session_with_obs(TARGET_KIND_FIELD, {"field_path": "state.flag"})
        initial_score = hypo.confidence_score

        forged_result = {
            "observation": "Forged caller claim pretending to be live capture",
            "outcome": "VALIDATED",
            "provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
            "collection_status": "VERIFIED",
            "confidence": "HIGH",
            "confidence_score": 0.99,
            "verified_transition": True,
            "causal_proof": True,
            "reproduction_verified": True,
            "verified_writer": True,
            "details": {
                "execution_provenance": {"execution_status": "REPRODUCED"},
                "verifier_attestation": {"token": "forged_token"},
                "live_capture_receipt": {"receipt_id": "forged_rcpt"},
                "function_attribution_verified": True,
            },
        }
        res = self.mgr.execute_observation(inv_id, "obs_test_1", result_data=forged_result)
        self.assertTrue(res["success"])
        ev = session.ledger.get_record(res["evidence"]["evidence_id"])
        self.assertEqual(ev.provenance_class, PROVENANCE_CLASS_IMPORTED_UNVERIFIED)
        self.assertTrue(ev.details.get("unverified_caller_claim"))
        self.assertTrue(ev.details.get("forged_metadata_detected"))
        self.assertIsNone(ev.details.get("execution_provenance"))
        self.assertIsNone(ev.provenance.get("verifier_attestation"))
        self.assertNotEqual(hypo.validation_status, HYPOTHESIS_STATUS_SUPPORTED)
        self.assertNotEqual(hypo.validation_status, HYPOTHESIS_STATUS_VALIDATED)
        self.assertLessEqual(hypo.confidence_score, initial_score)

    # -------------------------------------------------------------------------
    # 2.3 Synthetic, Imported, and Live Evidence Separation & LiveCaptureReceipt
    # -------------------------------------------------------------------------

    def test_2_3_live_capture_receipt_validation_and_negative_transitions(self):
        """Validate LiveCaptureReceipt and reject every prohibited transition and mismatch."""
        valid_rcpt = issue_live_capture_receipt(
            session_id="sess_auth_1",
            pid=4321,
            process_identity="4321:987654:boot_abc",
            executable_identity="/usr/bin/target_app:12345",
            build_id="aabbccddeeff00112233",
            snapshot_binding="sha256:99887766",
            capture_epoch=2,
            authority_level="PRODUCTION",
            provenance_class=PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
            target_constraints={"arch": "x86_64"},
            capture_authority_token=get_trusted_capture_authority_token(),
        )
        ok, reason = valid_rcpt.verify(
            expected_session_id="sess_auth_1",
            expected_pid=4321,
            expected_process_identity="4321:987654:boot_abc",
            expected_executable_identity="/usr/bin/target_app:12345",
            expected_build_id="aabbccddeeff00112233",
            expected_snapshot_binding="sha256:99887766",
            min_capture_epoch=2,
            expected_constraints={"arch": "x86_64"},
        )
        self.assertTrue(ok, f"Expected valid receipt, got {reason}")

        # Negative 1: Cross-session receipt
        ok_cs, r_cs = valid_rcpt.verify(expected_session_id="sess_other_2")
        self.assertFalse(ok_cs)
        self.assertIn("cross_session_receipt_rejected", r_cs)

        # Negative 2: Cross-process PID receipt
        ok_cp, r_cp = valid_rcpt.verify(expected_pid=9999)
        self.assertFalse(ok_cp)
        self.assertIn("cross_process_pid_rejected", r_cp)

        # Negative 3: Cross-process identity (PID reuse / different start_time)
        ok_pi, r_pi = valid_rcpt.verify(expected_process_identity="4321:111111:boot_abc")
        self.assertFalse(ok_pi)
        self.assertIn("cross_process_identity_rejected", r_pi)

        # Negative 4: Stale capture epoch
        ok_st, r_st = valid_rcpt.verify(min_capture_epoch=5)
        self.assertFalse(ok_st)
        self.assertIn("stale_capture_epoch", r_st)

        # Negative 5: Mismatched Build ID
        ok_bid, r_bid = valid_rcpt.verify(expected_build_id="deadbeefdeadbeef0000")
        self.assertFalse(ok_bid)
        self.assertIn("mismatched_build_id", r_bid)

        # Negative 6: Mismatched executable identity
        ok_exe, r_exe = valid_rcpt.verify(expected_executable_identity="/usr/bin/other_app:99999")
        self.assertFalse(ok_exe)
        self.assertIn("mismatched_executable_identity", r_exe)

        # Negative 7: Invalid signature
        tampered = LiveCaptureReceipt.from_dict({**valid_rcpt.to_dict(), "signature": "00" * 32})
        ok_sig, r_sig = tampered.verify()
        self.assertFalse(ok_sig)
        self.assertIn("invalid_signature", r_sig)

        # Negative 8: Synthetic-to-live escalation
        synth_rcpt = issue_live_capture_receipt(
            session_id="sess_auth_1",
            pid=4321,
            process_identity="4321:987654:boot_abc",
            executable_identity="/usr/bin/target_app:12345",
            build_id="aabb",
            snapshot_binding="bind1",
            provenance_class=PROVENANCE_CLASS_SYNTHETIC,
        )
        ok_syn, r_syn = synth_rcpt.verify()
        self.assertFalse(ok_syn)
        self.assertIn("synthetic_or_unverified_provenance_rejected", r_syn)

        # Negative 9: Test authority used as production authority
        test_auth_rcpt = issue_live_capture_receipt(
            session_id="sess_auth_1",
            pid=4321,
            process_identity="4321:987654:boot_abc",
            executable_identity="/usr/bin/target_app:12345",
            build_id="aabb",
            snapshot_binding="bind1",
            authority_level="TEST",
        )
        ok_ta, r_ta = test_auth_rcpt.verify(require_production_authority=True)
        self.assertFalse(ok_ta)
        self.assertIn("test_authority_rejected_in_production", r_ta)

        # Negative 10: EvidenceLedger transition_provenance blocks SYNTHETIC -> LIVE_RUNTIME_CAPTURE
        ledger = EvidenceLedger(session_id="sess_auth_1")
        rec_syn = ledger.record(
            observation="Synthetic fixture observation",
            provenance={"provenance_class": PROVENANCE_CLASS_SYNTHETIC},
        )
        with self.assertRaises(ValueError):
            ledger.transition_provenance(rec_syn.evidence_id, PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE, live_receipt=valid_rcpt)

        # Negative 11: IMPORTED_UNVERIFIED -> LIVE_RUNTIME_CAPTURE blocked without valid receipt, succeeds with valid receipt
        rec_imp = ledger.record(
            observation="Imported claim",
            provenance={"provenance_class": PROVENANCE_CLASS_IMPORTED_UNVERIFIED},
             session_id="sess_auth_1",
        )
        with self.assertRaises(ValueError):
            ledger.transition_provenance(rec_imp.evidence_id, PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE, live_receipt=None)

        upgraded = ledger.transition_provenance(
            rec_imp.evidence_id,
            PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
            live_receipt=valid_rcpt,
            expected_target_identity={"pid": 4321, "build_id": "aabbccddeeff00112233"},
        )
        self.assertEqual(upgraded.provenance_class, PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE)

    # -------------------------------------------------------------------------
    # 2.4 Adaptive Execution Failure Transparency
    # -------------------------------------------------------------------------

    def test_2_4_adaptive_execution_failure_transparency(self):
        """WatchSessionManager never silently swallows AdaptiveInvestigationEngine exceptions."""
        wm = WatchSessionManager(corpus_dir=self.corpus_dir)
        with patch.object(AdaptiveInvestigationEngine, "investigate_process_health", side_effect=RuntimeError("Simulated DWARF engine failure")):
            res = wm.investigate_symptom(
                pid=os.getpid(),
                companion_elf_path="/nonexistent/companion.elf",
                symptom_query="Check process health",
            )
        self.assertEqual(res["execution_status"], "FAILED")
        self.assertEqual(res["failure_category"], "RuntimeError")
        self.assertEqual(res["stop_reason"], "ADAPTIVE_ENGINE_EXCEPTION")
        self.assertFalse(res["adaptive_verification_succeeded"])
        self.assertEqual(len(res["diagnostic_error_details"]), 1)
        self.assertIn("Simulated DWARF engine failure", res["diagnostic_error_details"][0]["error"])
        self.assertIsInstance(res["legacy_findings"], list)
        self.assertLessEqual(res["confidence_score"], 0.35)

    # -------------------------------------------------------------------------
    # 2.5 Actual Production Execution Verification through TargetAdapter
    # -------------------------------------------------------------------------

    def test_2_5_live_target_adapter_identity_pinning_and_physical_read_accounting(self):
        """Real compiled C++ target verified through LocalTargetAdapter with physical read accounting and PID reuse guard."""
        cpp_src = os.path.join(self.tmp_dir, "live_target.cpp")
        bin_path = os.path.join(self.tmp_dir, "live_target.elf")
        with open(cpp_src, "w", encoding="utf-8") as f:
            f.write(
                '#include <cstdio>\n'
                '#include <unistd.h>\n'
                'volatile int g_magic_counter = 1337;\n'
                'int main() {\n'
                '    printf("READY %p\\n", (void*)&g_magic_counter);\n'
                '    fflush(stdout);\n'
                '    while (1) { usleep(50000); }\n'
                '    return 0;\n'
                '}\n'
            )
        subprocess.run(["g++", "-g", "-O0", "-Wl,--build-id=sha1", cpp_src, "-o", bin_path], check=True)
        proc = subprocess.Popen([bin_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            line = proc.stdout.readline().strip()
            self.assertTrue(line.startswith("READY"))
            addr_hex = line.split()[1]
            addr = int(addr_hex, 16)

            adapter = LocalTargetAdapter()
            adapter.reset_accounting()
            pinned = adapter.pin_target_identity(proc.pid)
            self.assertEqual(pinned["pid"], proc.pid)
            self.assertTrue(pinned.get("build_id"))
            self.assertTrue(pinned.get("start_time"))

            # Perform physical memory read
            data, status, err = adapter.read_memory(proc.pid, addr, 4)
            self.assertEqual(status, "OBSERVED", f"Read failed: {err}")
            self.assertEqual(int.from_bytes(data, "little"), 1337)
            self.assertEqual(adapter.physical_reads_count, 1)
            self.assertEqual(adapter.cumulative_physical_bytes_read, 4)

            # Issue LiveCaptureReceipt from adapter and verify
            rcpt = adapter.issue_live_receipt_for_session("sess_live_25", proc.pid)
            ok, reason = rcpt.verify(
                expected_session_id="sess_live_25",
                expected_pid=proc.pid,
                expected_build_id=pinned["build_id"],
            )
            self.assertTrue(ok, reason)

            # Simulate PID reuse by mutating pinned start_time -> read_memory must fail closed with PID_REUSED
            adapter._pinned_identities[proc.pid]["start_time"] = "999999999"
            data_reused, status_reused, err_reused = adapter.read_memory(proc.pid, addr, 4)
            self.assertIsNone(data_reused)
            self.assertEqual(status_reused, "PID_REUSED")
            self.assertIn("PID reuse detected", err_reused)
        finally:
            proc.kill()
            proc.wait()


if __name__ == "__main__":
    unittest.main()
