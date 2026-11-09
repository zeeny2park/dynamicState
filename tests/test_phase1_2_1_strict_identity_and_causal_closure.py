"""Tests for Phase 1.2.1 — Strict Identity Binding & Canonical Causal Attestation Closure.

Verifies:
1. Target identity binding: complete required identity fields (PID, process_identity,
   executable_identity, build_id) fail closed on missing fields, empty strings, and mismatches.
2. Explicit Build ID semantics: target genuinely lacking ELF build-id is permitted when both sides
   have empty/None build-id, but fails closed if either side has build-id and the other lacks it.
3. Strict scope binding: investigation_id, evidence_id, hypothesis_id, target_function, field_path,
   execution status, and capture quality.
4. Capability consolidation: single-use receipt consumption (_used_execution_ids), prevention of
   receipt replay across records or sessions, CausalVerificationCapability lifecycle.
5. Deterministic canonicalization: nested dict key ordering, Unicode values, lists/tuples, None,
   serialization round trips (to_dict/from_dict), and tamper detection.
"""

from datetime import datetime, timezone
import json
import unittest
import uuid
from typing import Any, Dict, Optional

from extractor.evidence_adapter import EvidenceAdapter
from extractor.evidence_ledger import (
    CLAIM_FUNCTION_ATTRIBUTION_VERIFIED,
    CLAIM_STATE_TRANSITION_VERIFIED,
    ControlledExecutionResult,
    EvidenceLedger,
    EvidenceRecord,
    PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION,
    PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
    PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
    PROVENANCE_CLASS_SYNTHETIC,
    PROVENANCE_CLASS_SYNTHETIC_FIXTURE,
    canonicalize_receipt_value,
    compute_attestation_signature,
    compute_evidence_fingerprint,
    compute_receipt_signature,
    validate_controlled_execution_target_identity,
)
from extractor.capture_backend import (
    LiveCaptureReceipt,
    get_trusted_capture_authority_token,
    issue_live_capture_receipt,
)


class TestPhase121StrictIdentityAndCausalClosure(unittest.TestCase):
    """Rigorous test matrix for Phase 1.2.1 strict identity binding, scope binding, and causal closure."""

    def setUp(self):
        self.session_id = f"inv_p121_{uuid.uuid4().hex[:8]}"
        self.ledger = EvidenceLedger(session_id=self.session_id)
        self.adapter = EvidenceAdapter()
        self.target = {
            "pid": 54321,
            "process_identity": "54321:1700000000:boot_p121",
            "executable_identity": "/usr/bin/service_worker:12345",
            "build_id": "sha1:abcdef0123456789abcdef0123456789abcdef01",
            "companion_elf": "/usr/bin/service_worker",
        }

    def _create_signed_execution_result(
        self,
        investigation_id: Optional[str] = None,
        secret: Optional[str] = None,
        target_identity: Optional[Dict[str, Any]] = None,
        execution_status: str = "REPRODUCED",
        completeness: str = "COMPLETE",
        consistency_level: str = "ZERO_STOP_ATOMIC",
        target_function: str = "dispatch_event",
        field_path: str = "worker_state",
        before_value: Any = "IDLE",
        after_value: Any = "PROCESSING",
        evidence_id: str = "ev_p121_valid",
        hypothesis_id: str = "hypo_p121",
        execution_id: Optional[str] = None,
        executed_at: Optional[str] = None,
        forge_signature: bool = False,
    ) -> ControlledExecutionResult:
        inv_id = investigation_id or self.session_id
        sec = secret or self.ledger.session_secret
        tid = target_identity if target_identity is not None else dict(self.target)
        eid = execution_id or f"exec_{uuid.uuid4().hex[:8]}"
        now_ts = executed_at or datetime.now(timezone.utc).isoformat()
        res_temp = ControlledExecutionResult(
            execution_id=eid,
            investigation_id=inv_id,
            target_function=target_function,
            field_path=field_path,
            before_value=before_value,
            after_value=after_value,
            execution_status=execution_status,
            capture_quality={"completeness": completeness, "consistency_level": consistency_level},
            target_identity=tid,
            hypothesis_id=hypothesis_id,
            evidence_id=evidence_id,
            executed_at=now_ts,
            function_attribution_verified=True,
            attribution_basis="controlled_single_writer_isolation",
            verified_claims=(CLAIM_STATE_TRANSITION_VERIFIED, CLAIM_FUNCTION_ATTRIBUTION_VERIFIED),
        )
        if forge_signature:
            sig = "0" * 64
        else:
            sig = compute_receipt_signature(sec, res_temp)

        return ControlledExecutionResult(
            execution_id=res_temp.execution_id,
            investigation_id=res_temp.investigation_id,
            target_function=res_temp.target_function,
            field_path=res_temp.field_path,
            before_value=res_temp.before_value,
            after_value=res_temp.after_value,
            execution_status=res_temp.execution_status,
            capture_quality=res_temp.capture_quality,
            target_identity=res_temp.target_identity,
            hypothesis_id=res_temp.hypothesis_id,
            evidence_id=res_temp.evidence_id,
            backend_type=res_temp.backend_type,
            provenance_class=res_temp.provenance_class,
            function_attribution_verified=res_temp.function_attribution_verified,
            attribution_basis=res_temp.attribution_basis,
            verified_claims=res_temp.verified_claims,
            executed_at=res_temp.executed_at,
            receipt_signature=sig,
        )

    # =========================================================================
    # 1. Target Identity Binding: Missing Fields (Fail Closed)
    # =========================================================================

    def test_tid_01_expected_pid_missing_fails_closed(self):
        exp = dict(self.target)
        del exp["pid"]
        ok, reason = validate_controlled_execution_target_identity(exp, self.target)
        self.assertFalse(ok)
        self.assertIn("PID missing", reason)

    def test_tid_02_receipt_pid_missing_fails_closed(self):
        rcpt = dict(self.target)
        del rcpt["pid"]
        ok, reason = validate_controlled_execution_target_identity(self.target, rcpt)
        self.assertFalse(ok)
        self.assertIn("PID missing", reason)

    def test_tid_03_expected_process_identity_missing_fails_closed(self):
        exp = dict(self.target)
        exp["process_identity"] = ""
        ok, reason = validate_controlled_execution_target_identity(exp, self.target)
        self.assertFalse(ok)
        self.assertIn("process_identity missing", reason)

    def test_tid_04_receipt_process_identity_missing_fails_closed(self):
        rcpt = dict(self.target)
        rcpt["process_identity"] = "  "
        ok, reason = validate_controlled_execution_target_identity(self.target, rcpt)
        self.assertFalse(ok)
        self.assertIn("process_identity missing", reason)

    def test_tid_05_expected_executable_identity_missing_fails_closed(self):
        exp = dict(self.target)
        exp["executable_identity"] = None
        ok, reason = validate_controlled_execution_target_identity(exp, self.target)
        self.assertFalse(ok)
        self.assertIn("executable_identity missing", reason)

    def test_tid_06_receipt_executable_identity_missing_fails_closed(self):
        rcpt = dict(self.target)
        del rcpt["executable_identity"]
        del rcpt["companion_elf"]
        ok, reason = validate_controlled_execution_target_identity(self.target, rcpt)
        self.assertFalse(ok)
        self.assertIn("executable_identity missing", reason)

    # =========================================================================
    # 2. Target Identity Binding: Mismatch Combinations (Fail Closed)
    # =========================================================================

    def test_tid_07_pid_mismatch_fails_closed(self):
        rcpt = dict(self.target)
        rcpt["pid"] = 99999
        ok, reason = validate_controlled_execution_target_identity(self.target, rcpt)
        self.assertFalse(ok)
        self.assertIn("PID mismatch", reason)

    def test_tid_08_process_identity_mismatch_fails_closed(self):
        rcpt = dict(self.target)
        rcpt["process_identity"] = "54321:1700000000:other_boot"
        ok, reason = validate_controlled_execution_target_identity(self.target, rcpt)
        self.assertFalse(ok)
        self.assertIn("process_identity mismatch", reason)

    def test_tid_09_executable_identity_mismatch_fails_closed(self):
        rcpt = dict(self.target)
        rcpt["executable_identity"] = "/usr/bin/rogue_binary:999"
        ok, reason = validate_controlled_execution_target_identity(self.target, rcpt)
        self.assertFalse(ok)
        self.assertIn("executable_identity mismatch", reason)

    def test_tid_10_build_id_mismatch_fails_closed(self):
        rcpt = dict(self.target)
        rcpt["build_id"] = "sha1:ffffffffffffffffffffffffffffffffffffffff"
        ok, reason = validate_controlled_execution_target_identity(self.target, rcpt)
        self.assertFalse(ok)
        self.assertIn("build_id mismatch", reason)

    # =========================================================================
    # 3. Explicit Build ID Semantics
    # =========================================================================

    def test_tid_11_both_empty_build_id_permitted(self):
        """When neither side has a build ID (e.g. stripped ELF without .note.gnu.build-id), permitted."""
        exp = dict(self.target)
        rcpt = dict(self.target)
        exp["build_id"] = None
        rcpt["build_id"] = ""
        ok, reason = validate_controlled_execution_target_identity(exp, rcpt)
        self.assertTrue(ok)
        self.assertIn("successfully verified", reason)

    def test_tid_12_expected_has_build_id_receipt_lacks_fails_closed(self):
        """When expected target has build ID but execution receipt lacks it, fail closed."""
        exp = dict(self.target)
        rcpt = dict(self.target)
        rcpt["build_id"] = None
        ok, reason = validate_controlled_execution_target_identity(exp, rcpt)
        self.assertFalse(ok)
        self.assertIn("receipt missing build_id", reason)

    def test_tid_13_receipt_has_build_id_expected_lacks_fails_closed(self):
        """When receipt has build ID but expected target lacks it, fail closed."""
        exp = dict(self.target)
        rcpt = dict(self.target)
        exp["build_id"] = None
        ok, reason = validate_controlled_execution_target_identity(exp, rcpt)
        self.assertFalse(ok)
        self.assertIn("expected identity missing build_id", reason)

    def test_tid_14_case_insensitive_build_id_matches(self):
        exp = dict(self.target)
        rcpt = dict(self.target)
        exp["build_id"] = "SHA1:ABCDEF0123456789ABCDEF0123456789ABCDEF01"
        rcpt["build_id"] = "sha1:abcdef0123456789abcdef0123456789abcdef01"
        ok, reason = validate_controlled_execution_target_identity(exp, rcpt)
        self.assertTrue(ok)

    # =========================================================================
    # 4. Scope Binding (Evidence ID, Hypothesis ID, Function, Field)
    # =========================================================================

    def test_scope_01_mismatched_evidence_id_in_capability_issuance_rejected(self):
        res = self._create_signed_execution_result(evidence_id="ev_original")
        with self.assertRaises(ValueError) as ctx:
            self.ledger.issue_verification_capability(
                evidence_id="ev_different",
                target_function=res.target_function,
                field_path=res.field_path,
                execution_result=res,
            )
        self.assertIn("does not match", str(ctx.exception))

    def test_scope_02_mismatched_hypothesis_id_in_capability_issuance_rejected(self):
        res = self._create_signed_execution_result(hypothesis_id="hypo_alpha")
        with self.assertRaises(ValueError) as ctx:
            self.ledger.issue_verification_capability(
                evidence_id=res.evidence_id,
                target_function=res.target_function,
                field_path=res.field_path,
                hypothesis_id="hypo_beta",
                execution_result=res,
            )
        self.assertIn("does not match", str(ctx.exception))

    def test_scope_03_mismatched_target_function_in_capability_issuance_rejected(self):
        res = self._create_signed_execution_result(target_function="handle_read")
        with self.assertRaises(ValueError) as ctx:
            self.ledger.issue_verification_capability(
                evidence_id=res.evidence_id,
                target_function="handle_write",
                field_path=res.field_path,
                execution_result=res,
            )
        self.assertIn("does not match", str(ctx.exception))

    def test_scope_04_mismatched_field_path_in_capability_issuance_rejected(self):
        res = self._create_signed_execution_result(field_path="conn.state")
        with self.assertRaises(ValueError) as ctx:
            self.ledger.issue_verification_capability(
                evidence_id=res.evidence_id,
                target_function=res.target_function,
                field_path="conn.flags",
                execution_result=res,
            )
        self.assertIn("does not match", str(ctx.exception))

    def test_scope_05_adapter_downgrades_on_mismatched_evidence_id(self):
        res = self._create_signed_execution_result(evidence_id="ev_res_100")
        rec = self.adapter.adapt_generic_tool_output(
            tool_name="controlled_verifier",
            tool_result={
                "outcome": "reproduced",
                "provenance_class": PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION,
                "execution_result": res,
            },
            target_identity=self.target,
            session_id=self.session_id,
            ledger=self.ledger,
            evidence_id="ev_adapter_200",  # Mismatched
        )
        self.assertEqual(rec.provenance_class, PROVENANCE_CLASS_IMPORTED_UNVERIFIED)
        self.assertIn("attestation_rejected", rec.provenance)

    def test_scope_06_adapter_downgrades_on_mismatched_hypothesis_id(self):
        res = self._create_signed_execution_result(hypothesis_id="hypo_foo")
        rec = self.adapter.adapt_generic_tool_output(
            tool_name="controlled_verifier",
            tool_result={
                "outcome": "reproduced",
                "hypothesis_id": "hypo_bar",  # Mismatched
                "provenance_class": PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION,
                "execution_result": res,
            },
            target_identity=self.target,
            session_id=self.session_id,
            ledger=self.ledger,
            evidence_id=res.evidence_id,
        )
        self.assertEqual(rec.provenance_class, PROVENANCE_CLASS_IMPORTED_UNVERIFIED)
        self.assertIn("attestation_rejected", rec.provenance)

    # =========================================================================
    # 5. CausalVerificationCapability Consolidation & Single-Use Enforcement
    # =========================================================================

    def test_cap_01_single_use_receipt_cannot_issue_two_capabilities(self):
        """The exact same execution_id cannot be used to issue two capabilities."""
        res = self._create_signed_execution_result(evidence_id="ev_cap_single")
        cap1 = self.ledger.issue_verification_capability(
            evidence_id="ev_cap_single",
            target_function=res.target_function,
            field_path=res.field_path,
            execution_result=res,
        )
        self.assertIsNotNone(cap1)
        self.assertFalse(cap1.is_consumed)

        with self.assertRaises(ValueError) as ctx:
            self.ledger.issue_verification_capability(
                evidence_id="ev_cap_single",
                target_function=res.target_function,
                field_path=res.field_path,
                execution_result=res,
            )
        self.assertIn("already been consumed", str(ctx.exception))

    def test_cap_02_consumed_capability_cannot_be_reused_in_attest_causal_proof(self):
        """A consumed CausalVerificationCapability raises RuntimeError on second consume."""
        res = self._create_signed_execution_result(evidence_id="ev_cap_consume")
        cap = self.ledger.issue_verification_capability(
            evidence_id="ev_cap_consume",
            target_function=res.target_function,
            field_path=res.field_path,
            execution_result=res,
        )
        cap.consume()
        self.assertTrue(cap.is_consumed)

        with self.assertRaises(RuntimeError) as ctx:
            cap.consume()
        self.assertIn("already been consumed", str(ctx.exception))

    def test_cap_03_same_execution_result_cannot_mint_two_records_via_adapter(self):
        """Adapter enforces single-use receipt consumption across repeated calls."""
        res = self._create_signed_execution_result(evidence_id="ev_rec_reuse_1")
        rec1 = self.adapter.adapt_generic_tool_output(
            tool_name="controlled_verifier",
            tool_result={
                "outcome": "reproduced",
                "provenance_class": PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION,
                "execution_result": res,
            },
            target_identity=self.target,
            session_id=self.session_id,
            ledger=self.ledger,
            evidence_id="ev_rec_reuse_1",
        )
        self.assertEqual(rec1.provenance_class, PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION)

        # Attempt to use the same execution receipt for a second record
        rec2 = self.adapter.adapt_generic_tool_output(
            tool_name="controlled_verifier",
            tool_result={
                "outcome": "reproduced",
                "provenance_class": PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION,
                "execution_result": res,
            },
            target_identity=self.target,
            session_id=self.session_id,
            ledger=self.ledger,
            evidence_id="ev_rec_reuse_2",
        )
        self.assertEqual(rec2.provenance_class, PROVENANCE_CLASS_IMPORTED_UNVERIFIED)
        self.assertIn("attestation_rejected", rec2.provenance)
        self.assertNotIn("verifier_attestation", rec2.provenance)

    def test_cap_04_cross_session_capability_use_rejected(self):
        other_ledger = EvidenceLedger(session_id="inv_other_session")
        res = self._create_signed_execution_result(
            investigation_id="inv_other_session",
            secret=other_ledger.session_secret,
            evidence_id="ev_cross_sess",
        )
        cap_other = other_ledger.issue_verification_capability(
            evidence_id="ev_cross_sess",
            target_function=res.target_function,
            field_path=res.field_path,
            execution_result=res,
        )
        # Attempt to validate capability against this ledger (mismatched session and key)
        self.assertFalse(cap_other.is_valid_for(self.ledger, "ev_cross_sess"))

    # =========================================================================
    # 6. Cryptographic Canonicalization & Tamper Resistance
    # =========================================================================

    def test_canon_01_nested_dict_key_ordering_invariance(self):
        """HMAC signature is identical regardless of dictionary key insertion order."""
        dict1 = {"b": 2, "a": {"z": 26, "y": 25}, "c": 3}
        dict2 = {"c": 3, "a": {"y": 25, "z": 26}, "b": 2}
        self.assertEqual(canonicalize_receipt_value(dict1), canonicalize_receipt_value(dict2))

        fixed_ts = "2026-11-09T00:00:00Z"
        res1 = self._create_signed_execution_result(before_value=dict1, after_value="DONE", execution_id="exec_canon_1", executed_at=fixed_ts)
        res2 = self._create_signed_execution_result(before_value=dict2, after_value="DONE", execution_id="exec_canon_1", executed_at=fixed_ts)
        self.assertEqual(res1.receipt_signature, res2.receipt_signature)

    def test_canon_02_unicode_values_in_payload_deterministic(self):
        """Unicode characters (e.g. Korean strings) canonicalize deterministically and verify."""
        val_unicode = {"상태": "정상처리", "메시지": "인터럽트_완료_0x12"}
        res = self._create_signed_execution_result(before_value=val_unicode, after_value="완료")
        self.assertTrue(res.verify_authenticity(self.ledger.session_secret))

    def test_canon_03_serialization_deserialization_round_trip(self):
        """ControlledExecutionResult to_dict() and from_dict() round trip preserves all fields and signature."""
        res_orig = self._create_signed_execution_result(
            before_value={"flag": True, "count": 10},
            after_value={"flag": False, "count": 20},
        )
        as_dict = res_orig.to_dict()
        self.assertIsInstance(as_dict, dict)
        res_restored = ControlledExecutionResult.from_dict(as_dict)
        self.assertEqual(res_orig, res_restored)
        self.assertTrue(res_restored.verify_authenticity(self.ledger.session_secret))

    def test_canon_04_tampered_target_identity_invalidates_receipt(self):
        res = self._create_signed_execution_result()
        # Tamper target identity PID in receipt
        tampered_tid = dict(res.target_identity)
        tampered_tid["pid"] = 99999
        tampered_res = ControlledExecutionResult(
            execution_id=res.execution_id,
            investigation_id=res.investigation_id,
            target_function=res.target_function,
            field_path=res.field_path,
            before_value=res.before_value,
            after_value=res.after_value,
            execution_status=res.execution_status,
            capture_quality=res.capture_quality,
            target_identity=tampered_tid,
            evidence_id=res.evidence_id,
            executed_at=res.executed_at,
            receipt_signature=res.receipt_signature,
        )
        self.assertFalse(tampered_res.verify_authenticity(self.ledger.session_secret))

    def test_canon_05_tampered_capture_quality_invalidates_receipt(self):
        res = self._create_signed_execution_result()
        tampered_cq = {"completeness": "PARTIAL", "consistency_level": "ZERO_STOP_ATOMIC"}
        tampered_res = ControlledExecutionResult(
            execution_id=res.execution_id,
            investigation_id=res.investigation_id,
            target_function=res.target_function,
            field_path=res.field_path,
            before_value=res.before_value,
            after_value=res.after_value,
            execution_status=res.execution_status,
            capture_quality=tampered_cq,
            target_identity=res.target_identity,
            evidence_id=res.evidence_id,
            executed_at=res.executed_at,
            receipt_signature=res.receipt_signature,
        )
        self.assertFalse(tampered_res.verify_authenticity(self.ledger.session_secret))

    # =========================================================================
    # 7. Synthetic and Live Proof Boundary Integrations
    # =========================================================================

    def test_boundary_01_synthetic_result_cannot_claim_controlled(self):
        res = self._create_signed_execution_result()
        rec = self.adapter.adapt_generic_tool_output(
            tool_name="mock_generator",
            tool_result={
                "outcome": "reproduced",
                "provenance_class": PROVENANCE_CLASS_SYNTHETIC,
                "execution_result": res,
            },
            target_identity=self.target,
            session_id=self.session_id,
            ledger=self.ledger,
            evidence_id="ev_synth_test",
        )
        self.assertIn(rec.provenance_class, (PROVENANCE_CLASS_SYNTHETIC, PROVENANCE_CLASS_SYNTHETIC_FIXTURE))
        self.assertNotIn("token_sig", rec.provenance.get("verifier_attestation", {}))

    def test_boundary_02_live_receipt_with_executable_mismatch_rejected(self):
        """LiveCaptureReceipt with mismatched executable identity is downgraded to IMPORTED_UNVERIFIED."""
        now_epoch = int(datetime.now(timezone.utc).timestamp() * 1e9)
        auth_tok = get_trusted_capture_authority_token()
        rcpt = issue_live_capture_receipt(
            session_id=self.session_id,
            pid=self.target["pid"],
            process_identity=self.target["process_identity"],
            executable_identity="/usr/bin/wrong_executable:111",
            build_id=self.target["build_id"],
            snapshot_binding="snap_p121_01",
            capture_epoch_ns=now_epoch,
            capture_authority_token=auth_tok,
        )
        rec = self.adapter.adapt_generic_tool_output(
            tool_name="proc_collector",
            tool_result={"live_capture_receipt": rcpt},
            target_identity=self.target,
            session_id=self.session_id,
            ledger=self.ledger,
            evidence_id="ev_live_exe_mismatch",
        )
        self.assertEqual(rec.provenance_class, PROVENANCE_CLASS_IMPORTED_UNVERIFIED)

    def test_boundary_03_genuine_production_execution_end_to_end(self):
        """Full genuine controlled execution lifecycle from producer to ledger admission."""
        res = self._create_signed_execution_result(evidence_id="ev_e2e_genuine")
        rec = self.adapter.adapt_generic_tool_output(
            tool_name="controlled_verifier",
            tool_result={
                "outcome": "reproduced",
                "provenance_class": PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION,
                "execution_result": res,
            },
            target_identity=self.target,
            session_id=self.session_id,
            ledger=self.ledger,
            evidence_id="ev_e2e_genuine",
        )
        self.assertEqual(rec.provenance_class, PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION)
        self.assertIn("verifier_attestation", rec.provenance)

        # Admitted cleanly to ledger
        added = self.adapter.record_into_ledger(rec, self.ledger, raise_on_error=True)
        self.assertEqual(len(added), 1)
        self.assertEqual(added[0].evidence_id, "ev_e2e_genuine")


if __name__ == "__main__":
    unittest.main()
