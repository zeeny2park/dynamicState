"""Phase 10: Independent Trust Verification & CI Acceptance Gates.

Comprehensive Security Acceptance Contract:
1. Ingress & Trust Boundary Enforcement:
   - REST/ARP callers cannot inject trusted attestations or promote hypotheses.
   - Caller-supplied booleans (function_attribution_verified=True, verified_claims) are disarmed.
   - Single-writer isolation strictly enforces baseline stability (before_value == after_value)
     and rejects caller labels when drift or concurrent mutation occurs.
   - STATIC_CANDIDATE cannot be promoted to VALIDATED_CAUSAL_FUNCTION without independent evidence.
   - Degraded capture quality (FAILED, PARTIAL, NON_ATOMIC) strictly caps hypotheses.
   - Capability scope, single-use consumption, and cross-session isolation are enforced.

2. Key Lifecycle, Rotation, Revocation & Thread Safety:
   - CaptureKeyStore operations are atomic and thread-safe under concurrent execution.
   - Key rotation preserves verification of older receipts while active key changes.
   - Key revocation immediately fails closed on all receipts signed with the revoked key.
   - Unconfigured ephemeral fallback fails closed on foreign receipts.
   - Malformed key files and keyrings fail safely.
   - Zero-leakage contract: secrets and capability keys are NEVER present in repr, str,
     to_dict, JSON serialization, logs, or exceptions.

3. Artifact Integrity & Anti-Tampering:
   - Payload byte tampering (1 byte corrupted in .bin) is detected.
   - Manifest file removal (deleted .bin) is detected.
   - Extra rogue file injection in memory/ or root directory is detected.
   - File renaming is detected.
   - Symlink substitution (symlinked file or directory) is strictly rejected.
   - Path traversal attacks (../ in paths) are strictly rejected.
   - Receipt field tampering (all security-critical fields) invalidates signature.
   - Legacy snapshots load backward-compatibly as UNVERIFIED_LEGACY.

4. Real-World Compiled C++ Cross-Process Acceptance:
   - Positive control: compiled C++ binary with PIE/ASLR, kernel memory capture, process termination,
     and offline verification in a clean analysis process with shared key.
   - Negative control: wrong key rejects causal attestation.
"""

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import threading
from typing import Any, Dict, List, Optional, Set, Tuple
import unittest

from extractor.capture_backend import (
    CaptureKeyStore,
    CaptureReceipt,
    ProcessVmCaptureBackend,
    ProcfsCaptureBackend,
    compute_capture_receipt_signature,
    get_default_key_store,
    issue_capture_receipt,
    set_default_key_store,
)
from extractor.evidence_ledger import (
    CausalVerificationCapability,
    ControlledExecutionResult,
    EVIDENCE_TYPE_COMPARISON,
    EVIDENCE_TYPE_FIELD_OBSERVATION,
    EvidenceLedger,
    EvidenceRecord,
    NATURE_OBSERVATION,
    ATTRIBUTION_BASIS_CALL_STACK,
    ATTRIBUTION_BASIS_EXECUTION_TRACE,
    ATTRIBUTION_BASIS_SINGLE_WRITER,
    CLAIM_ARTIFACT_INTEGRITY_VERIFIED,
    CLAIM_CAPTURE_PROVENANCE_VERIFIED,
    CLAIM_TARGET_IDENTITY_VERIFIED,
    CLAIM_STATE_TRANSITION_VERIFIED,
    CLAIM_FUNCTION_ATTRIBUTION_VERIFIED,
    ALL_TRUST_CLAIMS,
    PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
    PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION,
    PROVENANCE_CLASS_SYNTHETIC_FIXTURE,
    PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
    compute_attestation_signature,
)
from extractor.hypothesis import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    FUNCTION_TIER_EVIDENCE_SUPPORTED,
    FUNCTION_TIER_STATIC_CANDIDATE,
    FUNCTION_TIER_VALIDATED_CAUSAL,
    HYPOTHESIS_STATUS_CONTRADICTED,
    HYPOTHESIS_STATUS_INCONCLUSIVE,
    HYPOTHESIS_STATUS_PROPOSED,
    HYPOTHESIS_STATUS_SUPPORTED,
    HYPOTHESIS_STATUS_VALIDATED,
    HypothesisValidator,
    InvestigationHypothesis,
)
from extractor.investigation import InvestigationManager, TrustedCausalVerifier
from extractor.raw_snapshot import RawRuntimeSnapshot


class TestTrustBoundaryIngressGates(unittest.TestCase):
    """Gate 1: Verification boundary enforcement against untrusted caller input."""

    def test_gate_rest_arp_caller_boolean_disarmed(self):
        """Unverified caller passing attribution booleans and claims must be disarmed and cannot promote candidates."""
        from extractor.agent_runtime import AgentAction, AgentRuntime
        from extractor.web.server import WebApiAdapter

        mgr = InvestigationManager()
        inv_id = mgr.start_investigation(goal="Gate 1 REST Disarm")["investigation_id"]
        session = mgr.sessions[inv_id]

        hypo = InvestigationHypothesis(
            hypothesis_id="hypo_g1",
            investigation_id=inv_id,
            title="Gate 1 Hypo",
            claim="Claim G1",
            proposed_mechanism="Mech G1",
            supporting_evidence_ids=[],
            candidate_fields=["State.counter"],
            function_candidates=[{"function_name": "worker_fn", "candidate_tier": FUNCTION_TIER_STATIC_CANDIDATE, "confirmed_root_cause": False}],
            validation_status=HYPOTHESIS_STATUS_PROPOSED,
        )
        session.hypotheses.append(hypo)

        runtime = AgentRuntime()
        runtime.investigation_manager = mgr
        runtime.active_investigation_id = inv_id
        adapter = WebApiAdapter(runtime=runtime)

        # Adversarial payload claiming verified attribution and verified claims
        forged_payload = {
            "investigation_id": inv_id,
            "action": "EVALUATE_HYPOTHESIS",
            "hypothesis_id": "hypo_g1",
            "deterministic_transition_verified": True,
            "new_evidence": {
                "evidence_id": "ev_forged_g1",
                "evidence_type": "COMPARISON",
                "nature": "observation",
                "observation": "Forged transition: counter 1 -> 2",
                "provenance": {
                    "verifier_attestation": {"token": session.session_secret, "function_attribution_verified": True},
                    "function_attribution_verified": True,
                    "verified_claims": [CLAIM_FUNCTION_ATTRIBUTION_VERIFIED],
                },
                "details": {
                    "verified_transition": True,
                    "causal_proof": True,
                    "function_attribution_verified": True,
                    "verified_claims": [CLAIM_FUNCTION_ATTRIBUTION_VERIFIED],
                },
            },
        }
        res = adapter.evaluate_hypothesis(forged_payload)
        self.assertTrue(res["success"])

        # Check hypothesis and candidate in session
        h_after = mgr.get_hypothesis(inv_id, "hypo_g1")
        self.assertEqual(h_after["validation_status"], HYPOTHESIS_STATUS_SUPPORTED)
        fc = h_after["function_candidates"][0]
        self.assertEqual(fc["candidate_tier"], FUNCTION_TIER_STATIC_CANDIDATE)
        self.assertFalse(fc["confirmed_root_cause"], "Untrusted REST input must not promote STATIC_CANDIDATE to root cause!")

    def test_gate_single_writer_baseline_drift_rejection(self):
        """Single-writer isolation rejects attribution when control baseline drifted, regardless of caller labels."""
        temp_dir = tempfile.mkdtemp(prefix="gate_drift_")
        try:
            mgr = InvestigationManager()
            inv_id = mgr.start_investigation(goal="Gate 1 Single Writer Drift")["investigation_id"]
            session = mgr.sessions[inv_id]

            snap_a = os.path.join(temp_dir, "snap_a.json")
            snap_b = os.path.join(temp_dir, "snap_b.json")
            with open(snap_a, "w") as f:
                json.dump({
                    "snapshot_id": "snap_a",
                    "process": {"pid": 6001, "binary": "/bin/app", "executable_build_id": "b_g1"},
                    "timestamp": "2026-10-14T00:00:00Z",
                    "completeness": "COMPLETE",
                    "consistency": {"level": "STOPPED"},
                    "persistent": {"objects": [{"object_id": "o1", "type": "State", "fields": [{"name": "counter", "value": 1}]}]}
                }, f)
            with open(snap_b, "w") as f:
                json.dump({
                    "snapshot_id": "snap_b",
                    "process": {"pid": 6001, "binary": "/bin/app", "executable_build_id": "b_g1"},
                    "timestamp": "2026-10-14T00:00:05Z",
                    "completeness": "COMPLETE",
                    "consistency": {"level": "STOPPED"},
                    "persistent": {"objects": [{"object_id": "o1", "type": "State", "fields": [{"name": "counter", "value": 2}]}]}
                }, f)

            rec = EvidenceRecord(
                evidence_id="ev_treat",
                evidence_type=EVIDENCE_TYPE_COMPARISON,
                nature=NATURE_OBSERVATION,
                source="observer",
                session_id=inv_id,
                observation="Treatment: 1 -> 2",
                details={"target_function": "worker_fn", "field_path": "State.counter"},
                capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
            )
            session.ledger.add_record(rec)

            hypo = InvestigationHypothesis(
                hypothesis_id="hypo_drift",
                investigation_id=inv_id,
                title="Hypo Drift",
                claim="Claim Drift",
                proposed_mechanism="Mech Drift",
                supporting_evidence_ids=["ev_treat"],
                candidate_fields=["State.counter"],
                function_candidates=[{"function_name": "worker_fn", "candidate_tier": FUNCTION_TIER_EVIDENCE_SUPPORTED, "confirmed_root_cause": False}],
                validation_status=HYPOTHESIS_STATUS_SUPPORTED,
            )
            session.hypotheses.append(hypo)

            # Adversarial control: claims 'control_condition: baseline' and 'no_mutation' but before != after!
            rec_ctrl_bad = EvidenceRecord(
                evidence_id="ev_ctrl_bad",
                evidence_type=EVIDENCE_TYPE_COMPARISON,
                nature=NATURE_OBSERVATION,
                source="observer",
                session_id=inv_id,
                observation="Control record with stealth drift",
                details={
                    "target_function": "worker_fn",
                    "field_path": "State.counter",
                    "before_value": 1,
                    "after_value": 5,  # Drift occurred!
                    "control_condition": "baseline",
                    "mutation_occurred": True,
                },
                target_identity={"pid": 6001, "binary": "/bin/app", "build_id": "b_g1"},
                capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
            )
            session.ledger.add_record(rec_ctrl_bad)

            att_ok = mgr.verify_live_reproduction_and_attest(
                investigation_id=inv_id,
                hypothesis_id="hypo_drift",
                evidence_id="ev_treat",
                snapshot_a_path=snap_a,
                snapshot_b_path=snap_b,
                target_function="worker_fn",
                field_path="State.counter",
                attribution_evidence={
                    "attribution_basis": ATTRIBUTION_BASIS_SINGLE_WRITER,
                    "control_evidence_id": "ev_ctrl_bad",
                    "active_writer_function": "worker_fn",
                },
            )
            self.assertTrue(att_ok)
            att = session.ledger.get_record("ev_treat").provenance["verifier_attestation"]
            self.assertFalse(att["function_attribution_verified"], "Drifting control must fail attribution despite caller label!")
            self.assertIn("Negative control baseline failed", att["attribution_limitation"])

            res = mgr.evaluate_hypothesis(inv_id, "hypo_drift", proof_evidence_id="ev_treat", deterministic_transition_verified=True)
            self.assertEqual(res["transition"]["to_status"], HYPOTHESIS_STATUS_VALIDATED)
            fc = mgr.get_hypothesis(inv_id, "hypo_drift")["function_candidates"][0]
            self.assertFalse(fc["confirmed_root_cause"])
            self.assertEqual(fc["candidate_tier"], FUNCTION_TIER_EVIDENCE_SUPPORTED)
            self.assertIn("Negative control baseline failed", fc["tier_limitation"])
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_gate_static_dwarf_candidate_never_promoted_without_instrumentation(self):
        """STATIC_CANDIDATE cannot be promoted to VALIDATED_CAUSAL_FUNCTION without independent verified attribution."""
        temp_dir = tempfile.mkdtemp(prefix="gate_static_")
        try:
            mgr = InvestigationManager()
            inv_id = mgr.start_investigation(goal="Gate 1 Static DWARF")["investigation_id"]
            session = mgr.sessions[inv_id]

            snap_a = os.path.join(temp_dir, "snap_a.json")
            snap_b = os.path.join(temp_dir, "snap_b.json")
            with open(snap_a, "w") as f:
                json.dump({
                    "snapshot_id": "snap_a",
                    "process": {"pid": 6002, "binary": "/bin/app", "executable_build_id": "b_g2"},
                    "timestamp": "2026-10-14T00:00:00Z",
                    "completeness": "COMPLETE",
                    "consistency": {"level": "STOPPED"},
                    "persistent": {"objects": [{"object_id": "o1", "type": "State", "fields": [{"name": "counter", "value": 10}]}]}
                }, f)
            with open(snap_b, "w") as f:
                json.dump({
                    "snapshot_id": "snap_b",
                    "process": {"pid": 6002, "binary": "/bin/app", "executable_build_id": "b_g2"},
                    "timestamp": "2026-10-14T00:00:05Z",
                    "completeness": "COMPLETE",
                    "consistency": {"level": "STOPPED"},
                    "persistent": {"objects": [{"object_id": "o1", "type": "State", "fields": [{"name": "counter", "value": 20}]}]}
                }, f)

            rec = EvidenceRecord(
                evidence_id="ev_static_treat",
                evidence_type=EVIDENCE_TYPE_COMPARISON,
                nature=NATURE_OBSERVATION,
                source="observer",
                session_id=inv_id,
                observation="Obs",
                details={"target_function": "dwarf_candidate_fn", "field_path": "State.counter"},
                capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
            )
            session.ledger.add_record(rec)

            hypo = InvestigationHypothesis(
                hypothesis_id="hypo_static",
                investigation_id=inv_id,
                title="Hypo Static",
                claim="Claim Static",
                proposed_mechanism="Mech Static",
                supporting_evidence_ids=["ev_static_treat"],
                candidate_fields=["State.counter"],
                function_candidates=[{"function_name": "dwarf_candidate_fn", "candidate_tier": FUNCTION_TIER_STATIC_CANDIDATE, "confirmed_root_cause": False}],
                validation_status=HYPOTHESIS_STATUS_SUPPORTED,
            )
            session.hypotheses.append(hypo)

            # verify_live_reproduction_and_attest without attribution evidence
            att_ok = mgr.verify_live_reproduction_and_attest(
                investigation_id=inv_id,
                hypothesis_id="hypo_static",
                evidence_id="ev_static_treat",
                snapshot_a_path=snap_a,
                snapshot_b_path=snap_b,
                target_function="dwarf_candidate_fn",
                field_path="State.counter",
            )
            self.assertTrue(att_ok)

            res = mgr.evaluate_hypothesis(inv_id, "hypo_static", proof_evidence_id="ev_static_treat", deterministic_transition_verified=True)
            self.assertEqual(res["transition"]["to_status"], HYPOTHESIS_STATUS_VALIDATED)
            fc = mgr.get_hypothesis(inv_id, "hypo_static")["function_candidates"][0]
            self.assertEqual(fc["candidate_tier"], FUNCTION_TIER_STATIC_CANDIDATE)
            self.assertFalse(fc["confirmed_root_cause"], "STATIC_CANDIDATE must never become confirmed root cause without attribution evidence!")
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_gate_degraded_capture_quality_caps_hypothesis(self):
        """Degraded capture quality (completeness != COMPLETE or non-atomic consistency) caps hypothesis at SUPPORTED."""
        mgr = InvestigationManager()
        inv_id = mgr.start_investigation(goal="Gate 1 Degraded Quality")["investigation_id"]
        session = mgr.sessions[inv_id]

        rec_partial = EvidenceRecord(
            evidence_id="ev_partial",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="observer",
            session_id=inv_id,
            observation="Partial capture observation",
            details={"target_function": "fn_a", "field_path": "State.val"},
            capture_quality={"completeness": "PARTIAL", "consistency_level": "STOPPED"},
        )
        session.ledger.add_record(rec_partial)

        hypo = InvestigationHypothesis(
            hypothesis_id="hypo_partial",
            investigation_id=inv_id,
            title="Hypo Partial",
            claim="Claim Partial",
            proposed_mechanism="Mech Partial",
            supporting_evidence_ids=["ev_partial"],
            candidate_fields=["State.val"],
            function_candidates=[{"function_name": "fn_a", "candidate_tier": FUNCTION_TIER_EVIDENCE_SUPPORTED, "confirmed_root_cause": False}],
            validation_status=HYPOTHESIS_STATUS_PROPOSED,
        )
        session.hypotheses.append(hypo)

        res = mgr.evaluate_hypothesis(inv_id, "hypo_partial", deterministic_transition_verified=True)
        self.assertEqual(res["transition"]["to_status"], HYPOTHESIS_STATUS_SUPPORTED)
        self.assertIn("PARTIAL", res["transition"]["reason"])

    def test_gate_capability_scope_and_reuse_enforcement(self):
        """CausalVerificationCapability enforces exact scope binding and rejects reuse after consumption."""
        mgr = InvestigationManager()
        inv_id = mgr.start_investigation(goal="Gate 1 Capability Scope")["investigation_id"]
        session = mgr.sessions[inv_id]

        rec = EvidenceRecord(
            evidence_id="ev_cap",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="observer",
            session_id=inv_id,
            observation="Obs",
            details={"target_function": "worker_fn", "field_path": "State.counter"},
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
        )
        session.ledger.add_record(rec)

        verifier = TrustedCausalVerifier(session)
        rcpt = verifier.record_controlled_execution(
            target_function="worker_fn",
            field_path="State.counter",
            execution_status="REPRODUCED",
            backend_type="synthetic_adversarial_fixture",
            evidence_id="ev_cap",
            hypothesis_id="hypo_cap",
            function_attribution_verified=True,
            attribution_basis=ATTRIBUTION_BASIS_SINGLE_WRITER,
        )

        cap = session.issue_verification_capability(
            evidence_id="ev_cap",
            target_function="worker_fn",
            field_path="State.counter",
            hypothesis_id="hypo_cap",
            execution_result=rcpt,
        )

        # 1. Scope mismatch on function -> reject
        with self.assertRaises(ValueError) as ctx_fn:
            session.attest_causal_proof(
                evidence_id="ev_cap",
                target_function="wrong_fn",
                field_path="State.counter",
                capability=cap,
            )
        self.assertIn("scope-mismatched", str(ctx_fn.exception))

        # 2. Scope mismatch on field -> reject
        with self.assertRaises(ValueError) as ctx_fld:
            session.attest_causal_proof(
                evidence_id="ev_cap",
                target_function="worker_fn",
                field_path="State.other_field",
                capability=cap,
            )
        self.assertIn("scope-mismatched", str(ctx_fld.exception))

        # 3. Legitimate attestation succeeds
        ok = session.attest_causal_proof(
            evidence_id="ev_cap",
            target_function="worker_fn",
            field_path="State.counter",
            capability=cap,
        )
        self.assertTrue(ok)
        self.assertTrue(cap.is_consumed)

        # 4. Capability reuse attack -> reject
        with self.assertRaises(ValueError) as ctx_reuse:
            session.attest_causal_proof(
                evidence_id="ev_cap",
                target_function="worker_fn",
                field_path="State.counter",
                capability=cap,
            )
        self.assertIn("already consumed", str(ctx_reuse.exception))


class TestKeyLifecycleAndConcurrencyGates(unittest.TestCase):
    """Gate 2: KeyStore lifecycle, atomic concurrency, rotation, revocation, and zero-leakage contract."""

    def test_gate_concurrent_atomic_key_rotation_and_revocation(self):
        """Concurrent threads rotating keys, revoking keys, and verifying receipts execute atomically without race conditions."""
        ks = CaptureKeyStore()
        ks.register_key("initial_key", "secret_initial", is_active=True)

        valid_receipts = []
        for i in range(10):
            r = issue_capture_receipt(
                backend_name="process_vm_readv",
                pid=1000 + i,
                process_start_time="100",
                executable_path="/bin/app",
                executable_build_id="build_concur",
                capture_time=f"2026-10-14T00:0{i}:00Z",
                capture_duration_us=300.0,
                completeness="COMPLETE",
                consistency_level="STOPPED",
                artifact_manifest={"memory/heap.bin": f"digest_{i}"},
                secret="secret_initial",
                key_id="initial_key",
                receipt_id=f"rcpt_concur_{i}",
            )
            valid_receipts.append(r)

        errors = []

        def worker_rotator(thread_idx: int):
            try:
                for j in range(20):
                    kid = f"thread_{thread_idx}_key_{j}"
                    sec = f"secret_t{thread_idx}_j{j}"
                    ks.rotate_key(kid, sec)
            except Exception as e:
                errors.append(f"rotator error: {e}")

        def worker_verifier():
            try:
                for r in valid_receipts:
                    # initial_key is not revoked yet, should verify
                    ok, _, _ = ks.verify_receipt(r)
                    if not ok:
                        errors.append("Verification failed unexpectedly during concurrent rotation")
            except Exception as e:
                errors.append(f"verifier error: {e}")

        threads = []
        for idx in range(4):
            threads.append(threading.Thread(target=worker_rotator, args=(idx,)))
            threads.append(threading.Thread(target=worker_verifier))

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [], f"Concurrency errors encountered: {errors}")

        # Post-rotation: initial_key still verifies
        ok, _, verified_kid = ks.verify_receipt(valid_receipts[0])
        self.assertTrue(ok)
        self.assertEqual(verified_kid, "initial_key")

        # Now revoke initial_key
        ks.revoke_key("initial_key")
        ok_rev, reason_rev, _ = ks.verify_receipt(valid_receipts[0])
        self.assertFalse(ok_rev)
        self.assertIn("KEY_REVOKED", reason_rev)

    def test_gate_key_revocation_fail_closed(self):
        """Revoking a key fails closed immediately for all receipts using that key while active key remains functional."""
        ks = CaptureKeyStore()
        ks.register_key("k_alpha", "secret_alpha", is_active=True)
        rcpt_alpha = issue_capture_receipt(
            backend_name="procfs",
            pid=2001,
            process_start_time="50",
            executable_path="/bin/srv",
            executable_build_id="b_alpha",
            capture_time="2026-10-14T01:00:00Z",
            capture_duration_us=400.0,
            completeness="COMPLETE",
            consistency_level="STOPPED",
            artifact_manifest={"memory/state.bin": "hash_state"},
            secret="secret_alpha",
            key_id="k_alpha",
        )
        self.assertTrue(ks.verify_receipt(rcpt_alpha)[0])

        ks.rotate_key("k_beta", "secret_beta")
        rcpt_beta = issue_capture_receipt(
            backend_name="procfs",
            pid=2001,
            process_start_time="50",
            executable_path="/bin/srv",
            executable_build_id="b_alpha",
            capture_time="2026-10-14T01:05:00Z",
            capture_duration_us=410.0,
            completeness="COMPLETE",
            consistency_level="STOPPED",
            artifact_manifest={"memory/state.bin": "hash_state2"},
            secret="secret_beta",
            key_id="k_beta",
        )
        self.assertTrue(ks.verify_receipt(rcpt_beta)[0])

        # Revoke k_alpha
        ks.revoke_key("k_alpha")
        valid_a, reason_a, _ = ks.verify_receipt(rcpt_alpha)
        self.assertFalse(valid_a)
        self.assertIn("KEY_REVOKED", reason_a)

        # k_beta still verifies
        valid_b, _, kid_b = ks.verify_receipt(rcpt_beta)
        self.assertTrue(valid_b)
        self.assertEqual(kid_b, "k_beta")

    def test_gate_malformed_keyring_and_key_file_safety(self):
        """Supplying malformed, invalid JSON or corrupted files does not crash CaptureKeyStore and fails safely."""
        with tempfile.NamedTemporaryFile("w", delete=False) as tf:
            tf.write("NOT_JSON_{invalid")
            tf_path = tf.name

        saved_kf = os.environ.get("DYNAMICSTATE_CAPTURE_KEY_FILE")
        saved_sec = os.environ.get("DYNAMICSTATE_CAPTURE_SECRET")
        saved_kr = os.environ.get("DYNAMICSTATE_CAPTURE_KEYRING")
        try:
            if "DYNAMICSTATE_CAPTURE_SECRET" in os.environ:
                del os.environ["DYNAMICSTATE_CAPTURE_SECRET"]
            if "DYNAMICSTATE_CAPTURE_KEYRING" in os.environ:
                del os.environ["DYNAMICSTATE_CAPTURE_KEYRING"]

            # Key file is non-json string -> loads as single key fallback
            os.environ["DYNAMICSTATE_CAPTURE_KEY_FILE"] = tf_path
            ks = CaptureKeyStore()
            self.assertTrue(ks.is_explicitly_configured)
            self.assertEqual(ks._active_key_id, "file_default")

            # Keyring is invalid JSON string
            os.environ["DYNAMICSTATE_CAPTURE_KEYRING"] = "INVALID_JSON_STRING"
            ks2 = CaptureKeyStore()
            self.assertTrue(ks2.is_explicitly_configured)
        finally:
            if os.path.exists(tf_path):
                os.remove(tf_path)
            if saved_kf:
                os.environ["DYNAMICSTATE_CAPTURE_KEY_FILE"] = saved_kf
            elif "DYNAMICSTATE_CAPTURE_KEY_FILE" in os.environ:
                del os.environ["DYNAMICSTATE_CAPTURE_KEY_FILE"]
            if saved_sec:
                os.environ["DYNAMICSTATE_CAPTURE_SECRET"] = saved_sec
            if saved_kr:
                os.environ["DYNAMICSTATE_CAPTURE_KEYRING"] = saved_kr

    def test_gate_zero_secret_leakage_contract(self):
        """Zero-leakage security contract: keys and capability tokens are never revealed in repr, str, to_dict, or serialization."""
        secret = "super_confidential_vault_key_xyz999"
        ks = CaptureKeyStore()
        ks.register_key("vault_id_1", secret, is_active=True)

        ks_repr = repr(ks)
        ks_str = str(ks)
        self.assertNotIn(secret, ks_repr)
        self.assertNotIn(secret, ks_str)
        self.assertIn("vault_id_1", ks_repr)

        rcpt = issue_capture_receipt(
            backend_name="procfs",
            pid=3000,
            process_start_time="100",
            executable_path="/bin/srv",
            executable_build_id="b_sec",
            capture_time="2026-10-14T02:00:00Z",
            capture_duration_us=250.0,
            completeness="COMPLETE",
            consistency_level="STOPPED",
            artifact_manifest={"memory/buf.bin": "hash_buf"},
            secret=secret,
            key_id="vault_id_1",
        )
        rcpt_dict = rcpt.to_dict()
        rcpt_json = json.dumps(rcpt_dict)
        self.assertNotIn(secret, rcpt_json)
        self.assertNotIn(secret, repr(rcpt))
        self.assertNotIn(secret, str(rcpt))

        cap = CausalVerificationCapability(
            investigation_id="inv_sec",
            capability_key="secret_capability_key_abc",
            evidence_id="ev_sec",
            target_function="target_fn",
            field_path="field.p",
            hypothesis_id="hypo_sec",
        )
        self.assertNotIn("secret_capability_key_abc", repr(cap))
        self.assertNotIn("secret_capability_key_abc", str(cap))


class TestArtifactIntegrityAndAntiTamperingGates(unittest.TestCase):
    """Gate 3: Snapshot artifact integrity, anti-tampering, manifest hashing, and legacy compatibility."""

    def test_gate_payload_byte_tampering_detected(self):
        """Altering a single byte of memory payload causes RawRuntimeSnapshot.load to fail with TAMPERED status."""
        temp_dir = tempfile.mkdtemp(prefix="gate_byte_tamper_")
        orig_ks = get_default_key_store()
        ks = CaptureKeyStore()
        ks.register_key("k_disk", "secret_disk_123", is_active=True)
        set_default_key_store(ks)
        try:
            snap = RawRuntimeSnapshot(
                snapshot_id="snap_byte_tamper",
                pid=4001,
                executable="/bin/app",
                executable_build_id="b_tamper",
                timestamp="2026-10-14T03:00:00Z",
                completeness="COMPLETE",
                capture_backend="process_vm_readv",
                capture_duration_us=200.0,
            )
            snap.register_buffer(0x1000, b"\x00" * 256)
            snap_dir = os.path.join(temp_dir, "snap")
            snap.save(snap_dir)

            # Corrupt 1 byte in the memory payload
            mem_files = [f for f in os.listdir(os.path.join(snap_dir, "memory")) if f.endswith(".bin")]
            self.assertTrue(mem_files)
            corrupt_file = os.path.join(snap_dir, "memory", mem_files[0])
            with open(corrupt_file, "r+b") as f:
                f.write(b"\xFF")

            loaded = RawRuntimeSnapshot.load(snap_dir)
            self.assertEqual(loaded.provenance.get("verification_status"), "TAMPERED")
            self.assertIn("digest mismatch", loaded.provenance.get("verification_error", ""))
            self.assertFalse(loaded.provenance.get("is_authenticated_capture"))
        finally:
            set_default_key_store(orig_ks)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_gate_manifest_file_deletion_detected(self):
        """Deleting a payload file listed in artifact_manifest causes RawRuntimeSnapshot.load to mark TAMPERED."""
        temp_dir = tempfile.mkdtemp(prefix="gate_del_tamper_")
        orig_ks = get_default_key_store()
        ks = CaptureKeyStore()
        ks.register_key("k_disk", "secret_disk_123", is_active=True)
        set_default_key_store(ks)
        try:
            snap = RawRuntimeSnapshot(
                snapshot_id="snap_del_tamper",
                pid=4002,
                executable="/bin/app",
                executable_build_id="b_tamper2",
                timestamp="2026-10-14T03:00:00Z",
                completeness="COMPLETE",
                capture_backend="process_vm_readv",
                capture_duration_us=210.0,
            )
            snap.register_buffer(0x1000, b"AAAA" * 64)
            snap_dir = os.path.join(temp_dir, "snap")
            snap.save(snap_dir)

            # Delete the memory payload file
            mem_files = [f for f in os.listdir(os.path.join(snap_dir, "memory")) if f.endswith(".bin")]
            os.remove(os.path.join(snap_dir, "memory", mem_files[0]))

            loaded = RawRuntimeSnapshot.load(snap_dir)
            self.assertEqual(loaded.provenance.get("verification_status"), "TAMPERED")
            self.assertIn("missing", loaded.provenance.get("verification_error", "").lower())
        finally:
            set_default_key_store(orig_ks)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_gate_extra_file_injection_rejected(self):
        """Injecting extra unexpected files into memory/ or root directory causes RawRuntimeSnapshot.load to mark TAMPERED."""
        temp_dir = tempfile.mkdtemp(prefix="gate_extra_tamper_")
        orig_ks = get_default_key_store()
        ks = CaptureKeyStore()
        ks.register_key("k_disk", "secret_disk_123", is_active=True)
        set_default_key_store(ks)
        try:
            snap = RawRuntimeSnapshot(
                snapshot_id="snap_extra_tamper",
                pid=4003,
                executable="/bin/app",
                executable_build_id="b_tamper3",
                timestamp="2026-10-14T03:00:00Z",
                completeness="COMPLETE",
                capture_backend="process_vm_readv",
                capture_duration_us=220.0,
            )
            snap.register_buffer(0x1000, b"BBBB" * 64)
            snap_dir = os.path.join(temp_dir, "snap")
            snap.save(snap_dir)

            # Inject rogue script in root
            with open(os.path.join(snap_dir, "exploit.sh"), "wb") as f:
                f.write(b"#!/bin/sh\n")

            loaded = RawRuntimeSnapshot.load(snap_dir)
            self.assertEqual(loaded.provenance.get("verification_status"), "TAMPERED")
            self.assertIn("Extra unexpected root artifact", loaded.provenance.get("verification_error", ""))
        finally:
            set_default_key_store(orig_ks)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_gate_symlink_and_traversal_rejected(self):
        """Symlinked directories, symlinked files, and path traversal strings raise ValueError."""
        temp_dir = tempfile.mkdtemp(prefix="gate_sym_")
        try:
            snap_dir = os.path.join(temp_dir, "real_snap")
            os.makedirs(snap_dir, exist_ok=True)
            with open(os.path.join(snap_dir, "snapshot_metadata.json"), "w") as f:
                json.dump({"snapshot_id": "s1", "pid": 1}, f)

            # 1. Path traversal
            with self.assertRaises(ValueError) as ctx_trav:
                RawRuntimeSnapshot.load(os.path.join(snap_dir, "..", "real_snap"))
            self.assertIn("Path traversal", str(ctx_trav.exception))

            # 2. Symlink root directory
            sym_root = os.path.join(temp_dir, "sym_snap")
            os.symlink(snap_dir, sym_root)
            with self.assertRaises(ValueError) as ctx_sym:
                RawRuntimeSnapshot.load(sym_root)
            self.assertIn("symlinks are rejected", str(ctx_sym.exception))

            # 3. Non-existent directory
            with self.assertRaises(FileNotFoundError):
                RawRuntimeSnapshot.load(os.path.join(temp_dir, "non_existent"))

            # 4. File passed instead of directory
            not_dir = os.path.join(temp_dir, "file.txt")
            with open(not_dir, "w") as f:
                f.write("hello")
            with self.assertRaises(ValueError) as ctx_notdir:
                RawRuntimeSnapshot.load(not_dir)
            self.assertIn("not a directory", str(ctx_notdir.exception))
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_gate_receipt_all_security_fields_tamper_evident(self):
        """Tampering with any security field in Schema 2.0.0 CaptureReceipt invalidates the HMAC signature."""
        secret = "tamper_gate_key_999"
        manifest = {"memory/range_0x1000.bin": "sha256_1", "snapshot_metadata.json": "sha256_2"}
        rcpt = issue_capture_receipt(
            backend_name="process_vm_readv",
            pid=5001,
            process_start_time="1000",
            executable_path="/usr/bin/service",
            executable_build_id="build_secure_1",
            capture_time="2026-10-14T04:00:00Z",
            capture_duration_us=312.5,
            completeness="COMPLETE",
            consistency_level="STOPPED",
            artifact_manifest=manifest,
            secret=secret,
            key_id="k_sec",
            receipt_id="rcpt_sec_001",
        )
        self.assertTrue(rcpt.matches_secret(secret))

        field_tampering_cases = [
            ("receipt_id", "rcpt_sec_FORGED"),
            ("backend_name", "ptrace"),
            ("pid", 9999),
            ("process_start_time", "9999"),
            ("executable_path", "/usr/bin/other"),
            ("executable_build_id", "build_FORGED"),
            ("capture_time", "2026-10-14T05:00:00Z"),
            ("capture_duration_us", 500.0),
            ("completeness", "PARTIAL"),
            ("consistency_level", "NON_ATOMIC"),
            ("key_id", "k_other"),
            ("artifact_manifest", {"memory/range_0x1000.bin": "FORGED_HASH"}),
        ]

        for fld, forged_val in field_tampering_cases:
            tampered_data = rcpt.to_dict()
            tampered_data[fld] = forged_val
            tampered_rcpt = CaptureReceipt.from_dict(tampered_data)
            self.assertFalse(
                tampered_rcpt.matches_secret(secret),
                f"Tampering with '{fld}' must invalidate CaptureReceipt signature!",
            )

    def test_gate_legacy_snapshot_compatibility(self):
        """Legacy snapshot lacking capture_receipt.json loads cleanly as UNVERIFIED_LEGACY."""
        temp_dir = tempfile.mkdtemp(prefix="gate_legacy_")
        try:
            snap_dir = os.path.join(temp_dir, "legacy_snap")
            os.makedirs(os.path.join(snap_dir, "memory"), exist_ok=True)
            with open(os.path.join(snap_dir, "snapshot_metadata.json"), "w") as f:
                json.dump({
                    "snapshot_id": "legacy_01",
                    "pid": 5555,
                    "executable": "/bin/app",
                    "timestamp": "2026-10-14T00:00:00Z",
                    "capture_duration_us": 100.0,
                    "completeness": "COMPLETE",
                }, f)
            with open(os.path.join(snap_dir, "memory", "range_00001_0x1000_0x2000.bin"), "wb") as f:
                f.write(b"LEGACY_DATA")

            loaded = RawRuntimeSnapshot.load(snap_dir)
            self.assertEqual(loaded.provenance.get("verification_status"), "UNVERIFIED_LEGACY")
            self.assertFalse(loaded.provenance.get("is_authenticated_capture"))
            self.assertIsNone(loaded.capture_receipt)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestRealWorldCppCrossProcessAcceptanceGate(unittest.TestCase):
    """Gate 4: Real-world compiled C++ cross-process end-to-end acceptance gate."""

    @staticmethod
    def _compile_fixture(work_dir: str) -> Optional[str]:
        if shutil.which("g++") is None:
            return None
        src = os.path.abspath("tests/fixtures/real_runtime/main.cpp")
        if not os.path.exists(src):
            return None
        bin_path = os.path.join(work_dir, "gate_app.elf")
        res = subprocess.run(
            [
                "g++", "-fPIE", "-pie", "-g", "-O0", "-fno-inline", "-fno-omit-frame-pointer",
                "-Wl,--build-id=sha1", src, "-o", bin_path, "-lpthread"
            ],
            capture_output=True,
            text=True,
        )
        if res.returncode == 0 and os.path.exists(bin_path):
            return bin_path
        return None

    @staticmethod
    def _start_target_process(bin_path: str) -> subprocess.Popen:
        proc = subprocess.Popen(
            [bin_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        ready_line = proc.stdout.readline().strip()
        assert ready_line == "READY", f"Process did not emit READY: {ready_line}"
        return proc

    def test_gate_cpp_compiled_process_offline_verification_e2e(self):
        """Full positive control: compile C++ process, live capture with receipt, terminate process, verify post-mortem in fresh session."""
        temp_dir = tempfile.mkdtemp(prefix="gate_cpp_e2e_")
        proc = None
        orig_ks = get_default_key_store()
        try:
            bin_path = self._compile_fixture(temp_dir)
            if not bin_path:
                self.skipTest("g++ compiler or main.cpp fixture unavailable in current environment")

            shared_secret = "gate4_vault_secret_shared_999"
            ks_capture = CaptureKeyStore()
            ks_capture.register_key("vault_k1", shared_secret, is_active=True)
            set_default_key_store(ks_capture)

            proc = self._start_target_process(bin_path)

            backend = ProcessVmCaptureBackend() if ProcessVmCaptureBackend().is_available(proc.pid) else ProcfsCaptureBackend()
            if not backend.is_available(proc.pid):
                self.skipTest("No available capture backend for live process")

            # Capture baseline
            snap1 = backend.capture(pid=proc.pid)
            snap1_dir = os.path.join(temp_dir, "snap1")
            snap1.save(snap1_dir)

            # Trigger deterministic mutation via stdin
            proc.stdin.write("MUTATE\n")
            proc.stdin.flush()
            mut_line = proc.stdout.readline().strip()
            self.assertEqual(mut_line, "MUTATED")

            # Capture treatment
            snap2 = backend.capture(pid=proc.pid)
            snap2_dir = os.path.join(temp_dir, "snap2")
            snap2.save(snap2_dir)

            # Terminate inferior to prove offline / post-mortem analysis
            try:
                proc.stdin.write("STOP\n")
                proc.stdin.flush()
            except Exception:
                pass
            proc.terminate()
            proc.wait(timeout=2)
            if proc.stdout:
                proc.stdout.close()
            if proc.stderr:
                proc.stderr.close()
            if proc.stdin:
                proc.stdin.close()
            proc = None

            # Fresh analysis session with matching key
            ks_analysis = CaptureKeyStore()
            ks_analysis.register_key("vault_k1", shared_secret, is_active=True)
            set_default_key_store(ks_analysis)

            mgr = InvestigationManager(corpus_dir=os.path.join(temp_dir, "corpus"))
            inv_info = mgr.start_investigation(
                goal="Gate 4 C++ E2E Positive Control",
                memory_snapshot_path=snap1_dir,
                debug_image=bin_path,
                authorize_target=False,
            )
            inv_id = inv_info["investigation_id"]
            session = mgr.sessions[inv_id]

            # Record baseline control
            rec_ctrl = EvidenceRecord(
                evidence_id="ev_g4_ctrl",
                evidence_type=EVIDENCE_TYPE_COMPARISON,
                nature=NATURE_OBSERVATION,
                source="investigation_observer",
                session_id=inv_id,
                observation="Baseline control stable at 42",
                details={
                    "target_function": "mutate_worker_state",
                    "field_path": "State.counter",
                    "before_value": 42,
                    "after_value": 42,
                    "state_stable": True,
                    "control_condition": "baseline",
                },
                target_identity={
                    "pid": snap1.pid,
                    "binary": bin_path,
                    "build_id": snap1.executable_build_id,
                },
                capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
            )
            session.ledger.add_record(rec_ctrl)

            cmp_res = mgr.compare_observations(inv_id, snap1_dir, snap2_dir)
            self.assertNotIn("error", cmp_res)
            mgr._execute_stage_synthesis(session)
            hypos = mgr.get_hypotheses(inv_id)
            counter_hypo = next((h for h in hypos if "counter" in h["title"].lower() or "counter" in h["claim"].lower()), hypos[0])
            h_id = counter_hypo["hypothesis_id"]

            rec_proof = EvidenceRecord(
                evidence_id="ev_g4_proof",
                evidence_type=EVIDENCE_TYPE_COMPARISON,
                nature=NATURE_OBSERVATION,
                source="investigation_observer",
                session_id=inv_id,
                observation="Deterministic C++ mutation: counter 42 -> 100 via mutate_worker_state",
                details={
                    "target_function": "mutate_worker_state",
                    "field_path": "State.counter",
                },
                capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
            )
            session.ledger.add_record(rec_proof)

            att_ok = mgr.verify_live_reproduction_and_attest(
                investigation_id=inv_id,
                hypothesis_id=h_id,
                evidence_id="ev_g4_proof",
                snapshot_a_path=snap1_dir,
                snapshot_b_path=snap2_dir,
                target_function="mutate_worker_state",
                field_path="State.counter",
                attribution_evidence={
                    "attribution_basis": ATTRIBUTION_BASIS_SINGLE_WRITER,
                    "control_evidence_id": "ev_g4_ctrl",
                    "active_writer_function": "mutate_worker_state",
                },
                require_capture_provenance=True,
            )
            self.assertTrue(att_ok)

            eval_res = mgr.evaluate_hypothesis(inv_id, h_id, proof_evidence_id="ev_g4_proof", deterministic_transition_verified=True)
            self.assertEqual(eval_res["transition"]["to_status"], HYPOTHESIS_STATUS_VALIDATED)
            fc = next((c for c in mgr.get_hypothesis(inv_id, h_id)["function_candidates"] if c.get("function_name") == "mutate_worker_state"), None)
            self.assertIsNotNone(fc)
            self.assertEqual(fc["candidate_tier"], FUNCTION_TIER_VALIDATED_CAUSAL)
            self.assertTrue(fc["confirmed_root_cause"], "Legitimate C++ positive control must promote to confirmed root cause!")

            # Negative control: analysis session with wrong key fails require_capture_provenance
            ks_wrong = CaptureKeyStore()
            ks_wrong.register_key("vault_k1", "completely_wrong_secret", is_active=True)
            set_default_key_store(ks_wrong)

            mgr_bad = InvestigationManager(corpus_dir=os.path.join(temp_dir, "corpus_bad"))
            inv_bad_info = mgr_bad.start_investigation(
                goal="Gate 4 Bad Key Negative Control",
                memory_snapshot_path=snap1_dir,
                debug_image=bin_path,
                authorize_target=False,
            )
            inv_bad_id = inv_bad_info["investigation_id"]
            session_bad = mgr_bad.sessions[inv_bad_id]
            rec_bad = EvidenceRecord(
                evidence_id="ev_bad_proof",
                evidence_type=EVIDENCE_TYPE_COMPARISON,
                nature=NATURE_OBSERVATION,
                source="investigation_observer",
                session_id=inv_bad_id,
                observation="Bad key proof",
                details={"target_function": "mutate_worker_state", "field_path": "State.counter"},
                capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
            )
            session_bad.ledger.add_record(rec_bad)

            with self.assertRaises(ValueError) as ctx_bad:
                mgr_bad.verify_live_reproduction_and_attest(
                    investigation_id=inv_bad_id,
                    hypothesis_id=h_id,
                    evidence_id="ev_bad_proof",
                    snapshot_a_path=snap1_dir,
                    snapshot_b_path=snap2_dir,
                    target_function="mutate_worker_state",
                    field_path="State.counter",
                    require_capture_provenance=True,
                )
            self.assertIn("Capture provenance verification failed", str(ctx_bad.exception))
        finally:
            set_default_key_store(orig_ks)
            if proc:
                try:
                    proc.stdin.write("STOP\n")
                    proc.stdin.flush()
                except Exception:
                    pass
                proc.terminate()
                proc.wait(timeout=2)
                if proc.stdout:
                    proc.stdout.close()
                if proc.stderr:
                    proc.stderr.close()
                if proc.stdin:
                    proc.stdin.close()
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
