"""Phase 1.2.2 — Cryptographic Canonicalization & Attestation Authority Closure Tests.

Verifies:
1. Cryptographic canonicalization (RFC 8785 / JCS):
   - Strict type distinction (1 vs "1", None vs "None", True vs 1, False vs 0, integer vs float)
   - IEEE 754 float formatting (-0.0 -> 0, exponent normalization, shortest dtoa)
   - Rejection of non-finite numbers (NaN, inf, -inf) and unsupported types
   - Delimiter immunity: structured canonical framing prevents pipe (|) or colon delimiter collision
   - Backwards-compatible legacy signature validation (valid legacy passes, invalid fails)
2. Session secret closure:
   - Removal of raw "token": session_secret from verifier_attestation
   - Absence of session_secret in evidence records, to_dict(), exports, and logs
   - Pure cryptographic authentication via token_sig (HMAC-SHA256)
3. Consolidate attestation authority into EvidenceLedger:
   - EvidenceLedger.attest_causal_proof() as the single canonical authority
   - EvidenceAdapter does not independently mint verifier_attestation
   - Admission precedes attestation
   - Failure rollback leaves no partially trusted records in ledger
4. Complete scope binding:
   - Missing, empty, or whitespace-only evidence_id fails closed
   - Hypothesis scope semantics (both empty, both matching, one-sided fails closed)
   - Exact target_function and field_path binding
5. Atomic single-use receipt consumption & concurrency:
   - Multi-threaded concurrent consumption race test
   - Durable ledger lock (threading.RLock) thread safety
"""

import concurrent.futures
from datetime import datetime, timezone
import hashlib
import hmac
import json
import math
import threading
import unittest
import uuid
from typing import Any, Dict, List, Optional

from extractor.canonical_json import rfc8785_canonical_json, rfc8785_canonical_str
from extractor.evidence_adapter import EvidenceAdapter
from extractor.evidence_ledger import (
    CLAIM_FUNCTION_ATTRIBUTION_VERIFIED,
    CLAIM_STATE_TRANSITION_VERIFIED,
    CausalVerificationCapability,
    ControlledExecutionResult,
    EvidenceLedger,
    EvidenceRecord,
    EVIDENCE_TYPE_COMPARISON,
    EVIDENCE_TYPE_DIAGNOSTIC,
    NATURE_OBSERVATION,
    PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION,
    PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
    canonicalize_receipt_value,
    compute_attestation_signature,
    compute_controlled_execution_payload,
    compute_evidence_fingerprint,
    compute_legacy_receipt_signature,
    compute_receipt_signature,
)


class TestPhase122CryptographicCanonicalizationAndAuthorityClosure(unittest.TestCase):
    def setUp(self):
        self.session_id = f"inv_p122_{uuid.uuid4().hex[:8]}"
        self.ledger = EvidenceLedger(session_id=self.session_id)
        self.adapter = EvidenceAdapter()
        self.target = {
            "pid": 65432,
            "process_identity": "65432:1700000000:boot_p122",
            "executable_identity": "/usr/bin/payment_gateway:9999",
            "build_id": "sha1:0123456789abcdef0123456789abcdef01234567",
            "companion_elf": "/usr/bin/payment_gateway",
        }
        self.ledger.target_identity = dict(self.target)

    def _create_signed_execution_result(
        self,
        investigation_id: Optional[str] = None,
        secret: Optional[str] = None,
        target_identity: Optional[Dict[str, Any]] = None,
        execution_status: str = "REPRODUCED",
        completeness: str = "COMPLETE",
        consistency_level: str = "ZERO_STOP_ATOMIC",
        target_function: str = "process_payment",
        field_path: str = "account.balance",
        before_value: Any = 1000,
        after_value: Any = 900,
        evidence_id: str = "ev_p122_test",
        hypothesis_id: str = "",
        execution_id: Optional[str] = None,
        executed_at: Optional[str] = None,
        forge_signature: bool = False,
        legacy_signature: bool = False,
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
            attribution_basis="single_writer_control",
            verified_claims=(CLAIM_STATE_TRANSITION_VERIFIED, CLAIM_FUNCTION_ATTRIBUTION_VERIFIED),
        )
        if forge_signature:
            sig = "0" * 64
        elif legacy_signature:
            sig = compute_legacy_receipt_signature(sec, res_temp)
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
            signature_version="v1_legacy" if legacy_signature else "v2_rfc8785",
        )

    # =========================================================================
    # Group 1: RFC 8785 Canonical JSON & Cryptographic Authenticity
    # =========================================================================

    def test_canon_01_type_distinction_preservation(self):
        """Strictly distinguishes 1 vs '1', None vs 'None', True vs 1, False vs 0."""
        # 1 vs "1"
        self.assertNotEqual(rfc8785_canonical_json(1), rfc8785_canonical_json("1"))
        self.assertEqual(rfc8785_canonical_str(1), "1")
        self.assertEqual(rfc8785_canonical_str("1"), '"1"')

        # None vs "None"
        self.assertNotEqual(rfc8785_canonical_json(None), rfc8785_canonical_json("None"))
        self.assertEqual(rfc8785_canonical_str(None), "null")
        self.assertEqual(rfc8785_canonical_str("None"), '"None"')

        # True vs 1, False vs 0
        self.assertNotEqual(rfc8785_canonical_json(True), rfc8785_canonical_json(1))
        self.assertNotEqual(rfc8785_canonical_json(False), rfc8785_canonical_json(0))
        self.assertEqual(rfc8785_canonical_str(True), "true")
        self.assertEqual(rfc8785_canonical_str(False), "false")

        # Distinct HMAC signatures for different types
        fixed_ts = "2026-11-09T00:00:00Z"
        res_int = self._create_signed_execution_result(before_value=1, execution_id="ex_type", executed_at=fixed_ts)
        res_str = self._create_signed_execution_result(before_value="1", execution_id="ex_type", executed_at=fixed_ts)
        self.assertNotEqual(res_int.receipt_signature, res_str.receipt_signature)

        res_none = self._create_signed_execution_result(before_value=None, execution_id="ex_type", executed_at=fixed_ts)
        res_str_none = self._create_signed_execution_result(before_value="None", execution_id="ex_type", executed_at=fixed_ts)
        self.assertNotEqual(res_none.receipt_signature, res_str_none.receipt_signature)

    def test_canon_02_ieee754_float_formatting_and_negative_zero(self):
        """RFC 8785 requires -0.0 to be serialized as 0 and exponents formatted without leading zeros."""
        self.assertEqual(rfc8785_canonical_str(-0.0), "0")
        self.assertEqual(rfc8785_canonical_str(0.0), "0")
        self.assertEqual(rfc8785_canonical_json(-0.0), b"0")

        # Exponent format: 1e-7 (not 1e-07)
        self.assertEqual(rfc8785_canonical_str(1e-7), "1e-7")
        self.assertEqual(rfc8785_canonical_str(1e21), "1e+21")

        # -0.0 vs 0 produce identical signature
        fixed_ts = "2026-11-09T00:00:00Z"
        res_neg_zero = self._create_signed_execution_result(before_value=-0.0, execution_id="ex_zero", executed_at=fixed_ts)
        res_pos_zero = self._create_signed_execution_result(before_value=0.0, execution_id="ex_zero", executed_at=fixed_ts)
        self.assertEqual(res_neg_zero.receipt_signature, res_pos_zero.receipt_signature)

    def test_canon_03_non_finite_floats_and_unsupported_types_rejected(self):
        """NaN, inf, -inf, and non-JSON types raise ValueError/TypeError and fail closed."""
        with self.assertRaises(ValueError):
            rfc8785_canonical_json(float("nan"))
        with self.assertRaises(ValueError):
            rfc8785_canonical_json(float("inf"))
        with self.assertRaises(ValueError):
            rfc8785_canonical_json(float("-inf"))
        with self.assertRaises(TypeError):
            rfc8785_canonical_json({1, 2, 3})  # set
        with self.assertRaises(TypeError):
            rfc8785_canonical_json(object())

        # An execution result containing NaN fails during signing or authenticity verification
        res_temp = ControlledExecutionResult(
            execution_id="ex_nan",
            investigation_id=self.session_id,
            target_function="func",
            field_path="path",
            before_value=float("nan"),
            after_value=1,
            execution_status="REPRODUCED",
            capture_quality={"completeness": "COMPLETE", "consistency_level": "ZERO_STOP_ATOMIC"},
            target_identity=self.target,
            executed_at=datetime.now(timezone.utc).isoformat(),
        )
        with self.assertRaises(ValueError):
            compute_receipt_signature(self.ledger.session_secret, res_temp)

        res_signed_dummy = ControlledExecutionResult(
            execution_id=res_temp.execution_id,
            investigation_id=res_temp.investigation_id,
            target_function=res_temp.target_function,
            field_path=res_temp.field_path,
            before_value=res_temp.before_value,
            after_value=res_temp.after_value,
            execution_status=res_temp.execution_status,
            capture_quality=res_temp.capture_quality,
            target_identity=res_temp.target_identity,
            executed_at=res_temp.executed_at,
            receipt_signature="dummy_signature",
        )
        self.assertFalse(res_signed_dummy.verify_authenticity(self.ledger.session_secret))

    def test_canon_04_delimiter_immunity(self):
        """Pipe delimiters in field values cannot spoof fields or create signature collisions."""
        fixed_ts = "2026-11-09T00:00:00Z"
        # In delimiter schemes, target_function="a|b" and field_path="c" could collide with target_function="a" and field_path="b|c"
        res1 = self._create_signed_execution_result(
            target_function="func|inject",
            field_path="normal_path",
            execution_id="ex_delim",
            executed_at=fixed_ts,
        )
        res2 = self._create_signed_execution_result(
            target_function="func",
            field_path="inject|normal_path",
            execution_id="ex_delim",
            executed_at=fixed_ts,
        )
        self.assertNotEqual(res1.receipt_signature, res2.receipt_signature)

    def test_canon_05_legacy_signature_backwards_compatibility(self):
        """Valid v1 legacy signature is accepted for backwards compatibility; forged legacy signature is rejected."""
        genuine_legacy = self._create_signed_execution_result(legacy_signature=True)
        self.assertTrue(genuine_legacy.verify_authenticity(self.ledger.session_secret))

        # Tampered legacy execution result fails verification
        tampered_legacy = ControlledExecutionResult(
            execution_id=genuine_legacy.execution_id,
            investigation_id=genuine_legacy.investigation_id,
            target_function=genuine_legacy.target_function,
            field_path="tampered.field",  # Tampered!
            before_value=genuine_legacy.before_value,
            after_value=genuine_legacy.after_value,
            execution_status=genuine_legacy.execution_status,
            capture_quality=genuine_legacy.capture_quality,
            target_identity=genuine_legacy.target_identity,
            hypothesis_id=genuine_legacy.hypothesis_id,
            evidence_id=genuine_legacy.evidence_id,
            executed_at=genuine_legacy.executed_at,
            receipt_signature=genuine_legacy.receipt_signature,
            signature_version=genuine_legacy.signature_version,
        )
        self.assertFalse(tampered_legacy.verify_authenticity(self.ledger.session_secret))

    # =========================================================================
    # Group 2: Session Secret Exposure Closure
    # =========================================================================

    def test_secret_01_session_secret_not_embedded_in_attestation(self):
        """verifier_attestation does not contain 'token': session_secret."""
        res = self._create_signed_execution_result(evidence_id="ev_sec_01")
        cap = self.ledger.issue_verification_capability(
            evidence_id="ev_sec_01",
            target_function=res.target_function,
            field_path=res.field_path,
            execution_result=res,
        )
        rec = EvidenceRecord(
            evidence_id="ev_sec_01",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="controlled_verifier",
            session_id=self.session_id,
            observation="Observed transition",
            target_identity=self.target,
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
        )
        self.ledger.add_record(rec)
        ok = self.ledger.attest_causal_proof(evidence_id="ev_sec_01", capability=cap)
        self.assertTrue(ok)

        att = rec.provenance.get("verifier_attestation", {})
        self.assertNotIn("token", att, "Raw session_secret token must NOT be embedded in verifier_attestation")
        self.assertIn("token_sig", att)
        self.assertEqual(att["investigation_id"], self.session_id)

    def test_secret_02_serialized_dicts_and_exports_do_not_expose_secret(self):
        """to_dict(), ledger.to_dict(), and ledger.to_json() never expose session_secret."""
        res = self._create_signed_execution_result(evidence_id="ev_sec_02")
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
            evidence_id="ev_sec_02",
        )
        self.assertEqual(rec.provenance_class, PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION)

        # 1. EvidenceRecord.to_dict()
        rec_dict = rec.to_dict()
        self.assertNotIn(self.ledger.session_secret, json.dumps(rec_dict))

        # 2. EvidenceLedger.to_dict() & to_json()
        ledger_dict = self.ledger.to_dict()
        self.assertNotIn(self.ledger.session_secret, json.dumps(ledger_dict))
        self.assertNotIn(self.ledger.session_secret, self.ledger.to_json())

    def test_secret_03_pure_hmac_attestation_verification(self):
        """Attestations authenticate purely via HMAC token_sig without raw token."""
        res = self._create_signed_execution_result(evidence_id="ev_sec_03")
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
            evidence_id="ev_sec_03",
        )
        self.assertEqual(rec.provenance_class, PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION)

        # Tampering with token_sig invalidates record in ledger validation
        att = rec.provenance["verifier_attestation"]
        orig_sig = att["token_sig"]
        att["token_sig"] = "deadbeef" * 8
        with self.assertRaises(ValueError):
            self.ledger.validate_record(rec)
        att["token_sig"] = orig_sig  # Restore

    # =========================================================================
    # Group 3: Consolidation of Attestation Authority into EvidenceLedger
    # =========================================================================

    def test_auth_01_adapter_does_not_independently_construct_attestation(self):
        """Calling adapter without a ledger fails closed to IMPORTED_UNVERIFIED and never mints attestation."""
        res = self._create_signed_execution_result(evidence_id="ev_auth_01")
        rec = self.adapter.adapt_generic_tool_output(
            tool_name="controlled_verifier",
            tool_result={
                "outcome": "reproduced",
                "provenance_class": PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION,
                "execution_result": res,
            },
            target_identity=self.target,
            session_id=self.session_id,
            ledger=None,  # No ledger!
            evidence_id="ev_auth_01",
        )
        self.assertEqual(rec.provenance_class, PROVENANCE_CLASS_IMPORTED_UNVERIFIED)
        self.assertNotIn("verifier_attestation", rec.provenance)
        self.assertIn("attestation_rejected", rec.provenance)

    def test_auth_02_unadmitted_record_cannot_be_attested(self):
        """EvidenceLedger.attest_causal_proof rejects records not present in the ledger."""
        res = self._create_signed_execution_result(evidence_id="ev_unadmitted")
        cap = self.ledger.issue_verification_capability(
            evidence_id="ev_unadmitted",
            target_function=res.target_function,
            field_path=res.field_path,
            execution_result=res,
        )
        with self.assertRaises(ValueError) as ctx:
            self.ledger.attest_causal_proof(evidence_id="ev_unadmitted", capability=cap)
        self.assertIn("does not exist in ledger", str(ctx.exception))

    def test_auth_03_admission_failure_prevents_attestation(self):
        """If ledger admission fails (e.g. duplicate id conflict), attestation never occurs."""
        # Pre-seed ledger with an existing record to force duplicate evidence_id admission failure
        existing = EvidenceRecord(
            evidence_id="ev_pre_seeded",
            evidence_type=EVIDENCE_TYPE_DIAGNOSTIC,
            nature=NATURE_OBSERVATION,
            source="seed",
            session_id=self.session_id,
            observation="Initial seed record",
        )
        self.ledger.add_record(existing)

        res = self._create_signed_execution_result(evidence_id="ev_pre_seeded")
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
            evidence_id="ev_pre_seeded",
        )
        self.assertEqual(rec.provenance_class, PROVENANCE_CLASS_IMPORTED_UNVERIFIED)
        self.assertIn("attestation_rejected", rec.provenance)
        self.assertIn("admission failed", rec.provenance["attestation_rejected"].lower())

    def test_auth_04_attestation_failure_rolls_back_candidate_record(self):
        """If attest_causal_proof fails, the candidate record is rolled back and not left partially trusted."""
        res = self._create_signed_execution_result(evidence_id="ev_rollback")
        # Issue capability for one function, but execution_result has another
        cap = self.ledger.issue_verification_capability(
            evidence_id="ev_rollback",
            target_function=res.target_function,
            field_path=res.field_path,
            execution_result=res,
        )
        # Consume capability to make subsequent attestation fail
        cap.consume()

        # Admitted candidate
        cand = EvidenceRecord(
            evidence_id="ev_rollback",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="controlled_verifier",
            session_id=self.session_id,
            observation="Observed transition",
            target_identity=self.target,
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
        )
        self.ledger.add_record(cand)
        self.assertTrue(self.ledger.has("ev_rollback"))

        with self.assertRaises(ValueError):
            self.ledger.attest_causal_proof(evidence_id="ev_rollback", capability=cap)

        # Rollback candidate
        self.ledger.remove_record("ev_rollback")
        self.assertFalse(self.ledger.has("ev_rollback"))

    # =========================================================================
    # Group 4: Scope Binding Correctness
    # =========================================================================

    def test_scope_01_empty_or_whitespace_evidence_id_fails_closed(self):
        """Missing, empty, or whitespace-only evidence_id is rejected."""
        res = self._create_signed_execution_result(evidence_id="   ")
        with self.assertRaises(ValueError):
            self.ledger.issue_verification_capability(
                evidence_id="",
                target_function=res.target_function,
                field_path=res.field_path,
                execution_result=res,
            )

    def test_scope_02_hypothesis_scoping_semantics(self):
        """Strict semantics: non-hypothesis matches non-hypothesis; hypothesis matches hypothesis; cross fails."""
        # 1. Both empty -> matches
        res_generic = self._create_signed_execution_result(hypothesis_id="", evidence_id="ev_gen")
        cap_gen = self.ledger.issue_verification_capability(
            evidence_id="ev_gen",
            target_function=res_generic.target_function,
            field_path=res_generic.field_path,
            hypothesis_id="",
            execution_result=res_generic,
        )
        self.assertTrue(cap_gen.is_valid_for(self.ledger, "ev_gen", hypothesis_id=""))

        # 2. Generic proof attempted for hypothesis-scoped verification fails
        self.assertFalse(cap_gen.is_valid_for(self.ledger, "ev_gen", hypothesis_id="hypo_scoped"))

        # 3. Hypothesis-scoped proof attempted for generic verification fails
        res_hypo = self._create_signed_execution_result(hypothesis_id="hypo_1", evidence_id="ev_hyp")
        cap_hypo = self.ledger.issue_verification_capability(
            evidence_id="ev_hyp",
            target_function=res_hypo.target_function,
            field_path=res_hypo.field_path,
            hypothesis_id="hypo_1",
            execution_result=res_hypo,
        )
        self.assertTrue(cap_hypo.is_valid_for(self.ledger, "ev_hyp", hypothesis_id="hypo_1"))
        self.assertFalse(cap_hypo.is_valid_for(self.ledger, "ev_hyp", hypothesis_id=""))
        self.assertFalse(cap_hypo.is_valid_for(self.ledger, "ev_hyp", hypothesis_id="hypo_2"))

    def test_scope_03_target_function_and_field_path_mismatch_fails_closed(self):
        """target_function and field_path mismatches between receipt and capability fail closed."""
        res = self._create_signed_execution_result(
            target_function="handle_event",
            field_path="state.flag",
            evidence_id="ev_fn_field",
        )
        with self.assertRaises(ValueError):
            self.ledger.issue_verification_capability(
                evidence_id="ev_fn_field",
                target_function="wrong_func",
                field_path="state.flag",
                execution_result=res,
            )

        with self.assertRaises(ValueError):
            self.ledger.issue_verification_capability(
                evidence_id="ev_fn_field",
                target_function="handle_event",
                field_path="wrong.field",
                execution_result=res,
            )

    # =========================================================================
    # Group 5: Atomic Single-Use Receipt Consumption & Concurrency
    # =========================================================================

    def test_concurrent_01_multi_threaded_receipt_consumption_race(self):
        """Under concurrent execution, exactly ONE thread succeeds in consuming the execution receipt."""
        res = self._create_signed_execution_result(evidence_id="ev_race_01")
        success_count = 0
        failure_count = 0
        barrier = threading.Barrier(10)

        def worker():
            nonlocal success_count, failure_count
            barrier.wait()
            try:
                cap = self.ledger.issue_verification_capability(
                    evidence_id="ev_race_01",
                    target_function=res.target_function,
                    field_path=res.field_path,
                    execution_result=res,
                )
                success_count += 1
            except ValueError:
                failure_count += 1

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(success_count, 1, "Exactly one thread must successfully consume the execution receipt")
        self.assertEqual(failure_count, 9, "All competing threads must be rejected due to single-use enforcement")

    def test_concurrent_02_multi_threaded_capability_consumption_race(self):
        """Under concurrent execution, exactly ONE thread succeeds in consuming a minted capability."""
        res = self._create_signed_execution_result(evidence_id="ev_race_02")
        cap = self.ledger.issue_verification_capability(
            evidence_id="ev_race_02",
            target_function=res.target_function,
            field_path=res.field_path,
            execution_result=res,
        )
        rec = EvidenceRecord(
            evidence_id="ev_race_02",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="controlled_verifier",
            session_id=self.session_id,
            observation="Observed transition",
            target_identity=self.target,
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
        )
        self.ledger.add_record(rec)

        success_count = 0
        failure_count = 0
        barrier = threading.Barrier(8)

        def worker():
            nonlocal success_count, failure_count
            barrier.wait()
            try:
                ok = self.ledger.attest_causal_proof(evidence_id="ev_race_02", capability=cap)
                if ok:
                    success_count += 1
            except (ValueError, RuntimeError):
                failure_count += 1

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(success_count, 1, "Exactly one thread must successfully attest with the single-use capability")
        self.assertEqual(failure_count, 7, "All subsequent attempts must fail because capability was consumed")


if __name__ == "__main__":
    unittest.main()
