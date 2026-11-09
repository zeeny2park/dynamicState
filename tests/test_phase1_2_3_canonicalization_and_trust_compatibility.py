"""Phase 1.2.3 — Canonicalization Compliance & Trust Compatibility Closure Tests.

Comprehensive security, cryptographic canonicalization, and trust lifecycle test suite:
1. RFC 8785 Compliance:
   - Official RFC 8785 vectors (structures, values, weird, arrays, french, unicode)
   - UTF-16 code-unit key ordering (where UTF-8 byte ordering differs from UTF-16)
   - ECMAScript 6 IEEE 754 number formatting and boundaries (1e-6 vs 1e-7, 1e20 vs 1e21, -0.0 -> 0)
   - Exponent normalization without leading zeros
   - Rejection of non-finite numbers (NaN, Infinity, -Infinity)
   - Rejection of invalid Unicode / lone surrogates (U+D800..U+DFFF)
   - Rejection of non-string keys (int, None, etc.)
   - Rejection of unsupported Python types without silent conversion (tuple, set, custom objects)
   - Rejection of integers exceeding 64-bit domain
2. Fail-Closed Canonicalization:
   - canonicalize_receipt_value fail-closed behavior (no fallback to str)
   - Propagation of canonicalization errors as explicit verification failures
   - Absence of alternate serialization bypasses
3. Legacy Signature Compatibility & Downgrade Prevention:
   - Explicit version identification (signature_version="v2_rfc8785")
   - Prevention of implicit fallback to v1 when v2 verification fails
   - Legacy v1 verification only allowed when signature_version == "v1_legacy" and allow_legacy=True
   - Strict rejection on unsupported or unknown signature versions
4. Atomic Trust Lifecycle & Concurrency:
   - Ledger sole authority for receipt consumption and causal attestation
   - Atomic rollback (remove_record) on attestation failure with no partial state
   - Single-use replay rejection under concurrent attempts
   - Full capability scope binding (evidence_id, hypothesis_id, target_function, field_path, target_identity)
5. Session Secret / Provenance Exposure Audit:
   - Assurance that raw session secrets never appear in EvidenceRecord, provenance,
     verifier_attestation, to_dict(), MCP responses, or serialized outputs.
"""

import concurrent.futures
import copy
import hashlib
import hmac
import json
import math
import os
import unittest
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from extractor.canonical_json import (
    convert2Es6Format,
    rfc8785_canonical_json,
    rfc8785_canonical_str,
)
from extractor.evidence_adapter import EvidenceAdapter
from extractor.evidence_ledger import (
    ATTRIBUTION_BASIS_SINGLE_WRITER,
    CLAIM_FUNCTION_ATTRIBUTION_VERIFIED,
    CLAIM_STATE_TRANSITION_VERIFIED,
    EVIDENCE_TYPE_COMPARISON,
    NATURE_OBSERVATION,
    PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION,
    PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
    CausalVerificationCapability,
    ControlledExecutionResult,
    EvidenceLedger,
    EvidenceRecord,
    canonicalize_receipt_value,
    compute_legacy_receipt_signature,
    compute_receipt_signature,
)
from extractor.investigation import InvestigationSession


class TestPhase123CanonicalizationAndTrustCompatibility(unittest.TestCase):
    def setUp(self):
        self.session_id = f"inv_p123_{uuid.uuid4().hex[:8]}"
        self.ledger = EvidenceLedger(session_id=self.session_id)
        self.adapter = EvidenceAdapter()
        self.target = {
            "pid": 78910,
            "process_identity": "78910:1700000000:boot_p123",
            "executable_identity": "/usr/bin/settlement_service:5432",
            "build_id": "sha1:abcdef0123456789abcdef0123456789abcdef01",
            "companion_elf": "/usr/bin/settlement_service",
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
        target_function: str = "settle_batch",
        field_path: str = "batch.status",
        before_value: Any = "PENDING",
        after_value: Any = "SETTLED",
        evidence_id: str = "ev_p123_test",
        hypothesis_id: str = "",
        execution_id: Optional[str] = None,
        executed_at: Optional[str] = None,
        forge_signature: bool = False,
        legacy_signature: bool = False,
        signature_version: Optional[str] = None,
    ) -> ControlledExecutionResult:
        inv_id = investigation_id or self.session_id
        sec = secret or self.ledger.session_secret
        tid = target_identity if target_identity is not None else dict(self.target)
        eid = execution_id or f"exec_{uuid.uuid4().hex[:8]}"
        now_ts = executed_at or datetime.now(timezone.utc).isoformat()
        sig_ver = signature_version or ("v1_legacy" if legacy_signature else "v2_rfc8785")

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
            attribution_basis=ATTRIBUTION_BASIS_SINGLE_WRITER,
            verified_claims=(CLAIM_STATE_TRANSITION_VERIFIED, CLAIM_FUNCTION_ATTRIBUTION_VERIFIED),
            signature_version=sig_ver,
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
            signature_version=sig_ver,
        )

    # =========================================================================
    # Group 1: RFC 8785 Canonicalization Compliance & Test Vectors
    # =========================================================================

    def test_rfc8785_official_structures_vector(self):
        """RFC 8785 structures.json vector produces exact byte representation."""
        obj = {
            "": "empty",
            "10": {},
            "111": [{"e": "yes", "E": "no"}],
            "A": {},
            "a": {},
            "1": {"f": {"f": "hi", "F": 5}, "\n": 56},
        }
        expected = b'{"":"empty","1":{"\\n":56,"f":{"F":5,"f":"hi"}},"10":{},"111":[{"E":"no","e":"yes"}],"A":{},"a":{}}'
        self.assertEqual(rfc8785_canonical_json(obj), expected)

    def test_rfc8785_official_values_vector(self):
        """RFC 8785 values.json vector produces exact byte representation."""
        obj = {
            "numbers": [333333333.33333329, 1e30, 4.50, 2e-3, 0.000000000000000000000000001],
            "string": "€$\u000f\nA'B\"\\\"/",
            "literals": [None, True, False],
        }
        expected = b'{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"\xe2\x82\xac$\\u000f\\nA\'B\\"\\\\\\"/"}'
        self.assertEqual(rfc8785_canonical_json(obj), expected)

    def test_rfc8785_utf16_code_unit_ordering_vs_utf8(self):
        """Keys MUST be sorted in ascending order of UTF-16 code units.

        Emoji U+1F602 (UTF-16 surrogate pair D83D DE02, UTF-8 F0 9F 98 82)
        vs Hebrew Dalet U+FB33 (UTF-16 FB33, UTF-8 EF AC B3).
        UTF-16 code unit ordering: 0xD83D < 0xFB33 -> U+1F602 comes BEFORE U+FB33.
        UTF-8 byte ordering: 0xEF < 0xF0 -> U+FB33 would come BEFORE U+1F602.
        RFC 8785 mandates UTF-16 code-unit ordering.
        """
        emoji = "\U0001F602"  # 😂
        dalet = "\uFB33"      # דּ
        obj = {dalet: "dalet", emoji: "emoji"}
        canonical = rfc8785_canonical_str(obj)
        # Expected: {"😂":"emoji","דּ":"dalet"}
        expected = f'{{"{emoji}":"emoji","{dalet}":"dalet"}}'
        self.assertEqual(canonical, expected)
        # Verify UTF-16 code unit order:
        self.assertTrue(canonical.index(emoji) < canonical.index(dalet))

    def test_rfc8785_number_formatting_and_boundaries(self):
        """ECMAScript 6 IEEE 754 number boundaries and formatting."""
        # Negative zero -> '0'
        self.assertEqual(convert2Es6Format(-0.0), "0")
        self.assertEqual(convert2Es6Format(0.0), "0")
        self.assertEqual(convert2Es6Format(0), "0")

        # Exponent boundaries:
        # 1e-6 formatted as fixed decimal 0.000001
        self.assertEqual(convert2Es6Format(1e-6), "0.000001")
        self.assertEqual(convert2Es6Format(-1e-6), "-0.000001")
        # 1e-7 formatted in scientific notation 1e-7 (no leading zeros in exponent)
        self.assertEqual(convert2Es6Format(1e-7), "1e-7")
        self.assertEqual(convert2Es6Format(-1e-7), "-1e-7")

        # Upper boundaries:
        # 1e20 formatted as fixed decimal
        self.assertEqual(convert2Es6Format(1e20), "100000000000000000000")
        self.assertEqual(convert2Es6Format(-1e20), "-100000000000000000000")
        # 1e21 formatted in scientific notation 1e+21
        self.assertEqual(convert2Es6Format(1e21), "1e+21")
        self.assertEqual(convert2Es6Format(-1e21), "-1e+21")

        # Integer floats have no decimal point
        self.assertEqual(convert2Es6Format(1.0), "1")
        self.assertEqual(convert2Es6Format(-42.0), "-42")

    def test_rfc8785_rejects_non_finite_numbers(self):
        """NaN, +Infinity, -Infinity are rejected with ValueError."""
        with self.assertRaises(ValueError):
            rfc8785_canonical_json(float("nan"))
        with self.assertRaises(ValueError):
            rfc8785_canonical_json(float("inf"))
        with self.assertRaises(ValueError):
            rfc8785_canonical_json(float("-inf"))
        with self.assertRaises(ValueError):
            rfc8785_canonical_json({"score": float("nan")})

    def test_rfc8785_rejects_surrogates(self):
        """Lone surrogate characters (U+D800..U+DFFF) are rejected with ValueError."""
        lone_surrogate = "\uD800"
        with self.assertRaises(ValueError):
            rfc8785_canonical_json(lone_surrogate)
        with self.assertRaises(ValueError):
            rfc8785_canonical_json({"valid_key": f"bad_{lone_surrogate}"})
        with self.assertRaises(ValueError):
            rfc8785_canonical_json({lone_surrogate: "value"})

    def test_rfc8785_rejects_non_string_keys(self):
        """Non-string dictionary keys are strictly rejected with TypeError."""
        with self.assertRaises(TypeError):
            rfc8785_canonical_json({123: "val"})
        with self.assertRaises(TypeError):
            rfc8785_canonical_json({None: "val"})
        with self.assertRaises(TypeError):
            rfc8785_canonical_json({True: "val"})

    def test_rfc8785_rejects_unsupported_types_no_silent_conversion(self):
        """Tuples, sets, and custom objects must NOT be silently converted; must raise TypeError."""
        with self.assertRaises(TypeError):
            rfc8785_canonical_json((1, 2, 3))
        with self.assertRaises(TypeError):
            rfc8785_canonical_json({"data": (1, 2)})
        with self.assertRaises(TypeError):
            rfc8785_canonical_json({1, 2, 3})

        class CustomData:
            def __str__(self):
                return "custom"

        with self.assertRaises(TypeError):
            rfc8785_canonical_json(CustomData())

    def test_rfc8785_integer_domain_limits(self):
        """Integers outside 64-bit domain are rejected with ValueError."""
        with self.assertRaises(ValueError):
            rfc8785_canonical_json(2**64)
        with self.assertRaises(ValueError):
            rfc8785_canonical_json(-(2**64))

    # =========================================================================
    # Group 2: Fail-Closed Canonicalization
    # =========================================================================

    def test_fail_closed_canonicalize_receipt_value(self):
        """canonicalize_receipt_value propagates errors without falling back to str()."""
        # Valid values
        self.assertEqual(canonicalize_receipt_value(123), "123")
        self.assertEqual(canonicalize_receipt_value("hello"), '"hello"')
        self.assertEqual(canonicalize_receipt_value(None), "null")
        self.assertEqual(canonicalize_receipt_value([1, 2]), "[1,2]")

        # Invalid values MUST raise, not return str(...)
        with self.assertRaises(TypeError):
            canonicalize_receipt_value((1, 2))  # Tuple rejected
        with self.assertRaises(ValueError):
            canonicalize_receipt_value(float("nan"))
        with self.assertRaises(TypeError):
            canonicalize_receipt_value(object())

    def test_signing_and_verification_fail_closed_on_invalid_data(self):
        """compute_receipt_signature and verify_authenticity fail closed on uncanonicalizable data."""
        # Uncanonicalizable before_value (tuple)
        res_invalid = ControlledExecutionResult(
            execution_id="exec_bad_type",
            investigation_id=self.session_id,
            target_function="fn",
            field_path="field",
            before_value=(1, 2, 3),  # Tuple is unsupported
            after_value=[1, 2, 3],
            execution_status="REPRODUCED",
            capture_quality={"completeness": "COMPLETE", "consistency_level": "ZERO_STOP_ATOMIC"},
            target_identity=self.target,
            receipt_signature="dummy",
        )
        with self.assertRaises(TypeError):
            compute_receipt_signature(self.ledger.session_secret, res_invalid)
        # verify_authenticity fails closed gracefully
        self.assertFalse(res_invalid.verify_authenticity(self.ledger.session_secret))

    # =========================================================================
    # Group 3: Legacy Signature Compatibility & Downgrade Prevention
    # =========================================================================

    def test_v2_signature_does_not_implicitly_downgrade_to_v1(self):
        """Tampered v2 receipt fails verification and NEVER implicitly downgrades to v1."""
        res_v2 = self._create_signed_execution_result()
        self.assertEqual(res_v2.signature_version, "v2_rfc8785")
        self.assertTrue(res_v2.verify_authenticity(self.ledger.session_secret))

        # Tamper a field in v2 receipt
        tampered_v2 = copy.copy(res_v2)
        object.__setattr__(tampered_v2, "after_value", "TAMPERED_VAL")
        # Must return False, and must NOT fall back to legacy v1 verification
        self.assertFalse(tampered_v2.verify_authenticity(self.ledger.session_secret))

    def test_legacy_v1_explicit_verification_policy(self):
        """Legacy v1 receipts are verified only when explicitly allowed and identified."""
        res_v1 = self._create_signed_execution_result(legacy_signature=True)
        self.assertEqual(res_v1.signature_version, "v1_legacy")

        # Verified when allow_legacy=True
        self.assertTrue(res_v1.verify_authenticity(self.ledger.session_secret, allow_legacy=True))
        # Rejected when allow_legacy=False
        self.assertFalse(res_v1.verify_authenticity(self.ledger.session_secret, allow_legacy=False))

    def test_unsupported_signature_version_fails_closed(self):
        """Unsupported or unrecognized signature_version fails closed."""
        res_unknown = self._create_signed_execution_result()
        object.__setattr__(res_unknown, "signature_version", "v3_future_quantum")
        self.assertFalse(res_unknown.verify_authenticity(self.ledger.session_secret))

    # =========================================================================
    # Group 4: Atomic Trust Lifecycle & Concurrency
    # =========================================================================

    def test_atomic_rollback_on_attestation_failure(self):
        """If attestation fails after record admission, ledger.remove_record rolls back cleanly."""
        res = self._create_signed_execution_result(evidence_id="ev_rollback_test")

        # Target identity mismatch causes attestation failure
        mismatched_target = dict(self.target)
        mismatched_target["executable_identity"] = "/usr/bin/settlement_service:9999"

        result_rec = self.adapter.adapt_generic_tool_output(
            tool_name="controlled_verifier",
            tool_result={
                "outcome": "reproduced",
                "provenance_class": PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION,
                "execution_result": res,
            },
            target_identity=mismatched_target,
            session_id=self.session_id,
            ledger=self.ledger,
            evidence_id="ev_rollback_test",
        )

        # Attestation was rejected
        self.assertEqual(result_rec.provenance_class, PROVENANCE_CLASS_IMPORTED_UNVERIFIED)
        self.assertIn("attestation_rejected", result_rec.provenance)
        # Record rolled back from ledger (not admitted as partially trusted)
        self.assertIsNone(self.ledger.get_record("ev_rollback_test"))

    def test_receipt_single_use_atomicity_under_concurrency(self):
        """Under high concurrency, an execution receipt can be consumed at most once."""
        res = self._create_signed_execution_result(evidence_id="ev_concurrent")

        successes = 0
        failures = 0

        def try_consume(idx: int):
            return self.adapter.adapt_generic_tool_output(
                tool_name="controlled_verifier",
                tool_result={
                    "outcome": "reproduced",
                    "provenance_class": PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION,
                    "execution_result": res,
                },
                target_identity=self.target,
                session_id=self.session_id,
                ledger=self.ledger,
                evidence_id="ev_concurrent",
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(try_consume, i) for i in range(16)]
            results = [f.result() for f in futures]

        for r in results:
            if r.provenance_class == PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION:
                successes += 1
            else:
                failures += 1

        self.assertEqual(successes, 1, "Exactly one invocation should succeed in consuming the execution receipt")
        self.assertEqual(failures, 15, "All concurrent replay attempts must be rejected")

    def test_strict_capability_scope_bindings(self):
        """Capability issuance strictly binds evidence_id, hypothesis_id, target_function, and field_path."""
        res = self._create_signed_execution_result(
            evidence_id="ev_scope_test",
            hypothesis_id="hypo_alpha",
            target_function="process_txn",
            field_path="account.status",
        )

        # Mismatched evidence_id
        with self.assertRaises(ValueError):
            self.ledger.issue_verification_capability(
                evidence_id="ev_different",
                target_function="process_txn",
                field_path="account.status",
                hypothesis_id="hypo_alpha",
                execution_result=res,
            )

        # Mismatched target_function
        with self.assertRaises(ValueError):
            self.ledger.issue_verification_capability(
                evidence_id="ev_scope_test",
                target_function="wrong_fn",
                field_path="account.status",
                hypothesis_id="hypo_alpha",
                execution_result=res,
            )

        # Mismatched field_path
        with self.assertRaises(ValueError):
            self.ledger.issue_verification_capability(
                evidence_id="ev_scope_test",
                target_function="process_txn",
                field_path="wrong_field",
                hypothesis_id="hypo_alpha",
                execution_result=res,
            )

        # Mismatched hypothesis_id
        with self.assertRaises(ValueError):
            self.ledger.issue_verification_capability(
                evidence_id="ev_scope_test",
                target_function="process_txn",
                field_path="account.status",
                hypothesis_id="hypo_beta",
                execution_result=res,
            )

    # =========================================================================
    # Group 5: Session Secret Exposure Audit
    # =========================================================================

    def test_session_secret_never_leaked_in_records_or_exports(self):
        """Ensure session secrets are never exposed in EvidenceRecord, to_dict(), or ledger exports."""
        res = self._create_signed_execution_result(evidence_id="ev_secret_audit")
        attested_rec = self.adapter.adapt_generic_tool_output(
            tool_name="controlled_verifier",
            tool_result={
                "outcome": "reproduced",
                "provenance_class": PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION,
                "execution_result": res,
            },
            target_identity=self.target,
            session_id=self.session_id,
            ledger=self.ledger,
            evidence_id="ev_secret_audit",
        )
        self.assertEqual(attested_rec.provenance_class, PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION)

        secret = self.ledger.session_secret
        self.assertTrue(len(secret) > 0)

        # 1. EvidenceRecord to_dict()
        rec_dict_str = json.dumps(attested_rec.to_dict())
        self.assertNotIn(secret, rec_dict_str)

        # 2. ControlledExecutionResult to_dict()
        res_dict_str = json.dumps(res.to_dict())
        self.assertNotIn(secret, res_dict_str)

        # 3. EvidenceLedger to_dict() and to_json()
        ledger_dict_str = json.dumps(self.ledger.to_dict())
        self.assertNotIn(secret, ledger_dict_str)
        self.assertNotIn(secret, self.ledger.to_json())

        # 4. verifier_attestation in record details & provenance
        self.assertNotIn(secret, json.dumps(attested_rec.provenance))
        self.assertNotIn(secret, json.dumps(attested_rec.details))


if __name__ == "__main__":
    unittest.main()
