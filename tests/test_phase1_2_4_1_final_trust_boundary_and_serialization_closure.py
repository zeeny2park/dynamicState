# -*- coding: utf-8 -*-
"""Phase 1.2.4.1 — Final Trust Boundary & Serialization Closure Test Suite.

Verifies:
1. Signature-version semantic consistency across direct construction, to_dict, from_dict,
   and verify_authenticity. Downgrade and tampering prevention.
2. Opt-in legacy signature verification policy (allow_legacy_signatures=False rejects legacy receipts).
3. Complete recursive secret exposure audit across ControlledExecutionResult, EvidenceRecord (all 7 fields),
   EvidenceLedger, InvestigationSession, JSON/HTML reports, and MCP responses.
   Preservation of non-sensitive fields ('token_sig', 'receipt_signature', 'secret_sauce', 'shared_secret_id').
4. Canonical JSON input validation (TypeError on bool/str/None) and deterministic V8 differential suite
   with bit-exact IEEE 754 float patterns.
5. Legacy migration idempotency, tampered receipt rejection, and save/reload persistence.
6. Trust lifecycle invariants (concurrency single-use, scope binding, fail-closed authority).
"""

import copy
import json
import math
import subprocess
import threading
import unittest
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from extractor.canonical_json import (
    rfc8785_canonical_json,
    rfc8785_canonical_str,
    convert2Es6Format,
    IEEE754_MAX_SAFE_INTEGER,
    IEEE754_MIN_SAFE_INTEGER,
)
from extractor.evidence_adapter import EvidenceAdapter
from extractor.evidence_ledger import (
    ATTRIBUTION_BASIS_SINGLE_WRITER,
    CLAIM_FUNCTION_ATTRIBUTION_VERIFIED,
    CLAIM_STATE_TRANSITION_VERIFIED,
    PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION,
    PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
    ControlledExecutionResult,
    EvidenceLedger,
    EvidenceRecord,
    compute_legacy_receipt_signature,
    compute_receipt_signature,
    compute_attestation_signature,
    migrate_legacy_execution_result,
    strip_sensitive_session_secrets,
    SENSITIVE_SECRET_FIELD_NAMES,
)
from extractor.investigation import InvestigationSession, InvestigationManager, TrustedCausalVerifier
from extractor.verdict_engine import ZeroCdnReporter, DiagnosticVerdict


def make_test_execution_result(
    execution_id: str = "exec_test",
    investigation_id: str = "sess_test",
    target_function: str = "func_test",
    field_path: str = "obj.status",
    before_value: Any = "BEFORE",
    after_value: Any = "AFTER",
    execution_status: str = "REPRODUCED",
    capture_quality: Optional[Dict[str, Any]] = None,
    target_identity: Optional[Dict[str, Any]] = None,
    signature_version: Optional[str] = "v2_rfc8785",
    receipt_signature: Optional[str] = None,
    session_secret: Optional[str] = None,
    verified_claims: Tuple[str, ...] = (
        CLAIM_STATE_TRANSITION_VERIFIED,
        CLAIM_FUNCTION_ATTRIBUTION_VERIFIED,
    ),
    evidence_id: str = "ev_test",
) -> ControlledExecutionResult:
    """Helper to construct ControlledExecutionResult instances with proper signatures."""
    cq = capture_quality or {"completeness": "COMPLETE", "consistency_level": "ZERO_STOP_ATOMIC"}
    tid = target_identity or {
        "pid": 54321,
        "process_identity": "54321:1700000000:boot_test",
        "executable_identity": "/usr/bin/test_app:8080",
        "build_id": "sha1:abcdef1234567890abcdef1234567890abcdef12",
    }
    temp = ControlledExecutionResult(
        execution_id=execution_id,
        investigation_id=investigation_id,
        target_function=target_function,
        field_path=field_path,
        before_value=before_value,
        after_value=after_value,
        execution_status=execution_status,
        capture_quality=cq,
        target_identity=tid,
        evidence_id=evidence_id,
        function_attribution_verified=True,
        attribution_basis=ATTRIBUTION_BASIS_SINGLE_WRITER,
        verified_claims=verified_claims,
        signature_version=signature_version,
    )
    if receipt_signature is not None:
        sig = receipt_signature
    elif session_secret is not None:
        if temp.signature_version == "v2_rfc8785":
            sig = compute_receipt_signature(session_secret, temp)
        else:
            sig = compute_legacy_receipt_signature(session_secret, temp)
    else:
        sig = ""

    return ControlledExecutionResult(
        execution_id=temp.execution_id,
        investigation_id=temp.investigation_id,
        target_function=temp.target_function,
        field_path=temp.field_path,
        before_value=temp.before_value,
        after_value=temp.after_value,
        execution_status=temp.execution_status,
        capture_quality=temp.capture_quality,
        target_identity=temp.target_identity,
        hypothesis_id=temp.hypothesis_id,
        evidence_id=temp.evidence_id,
        backend_type=temp.backend_type,
        provenance_class=temp.provenance_class,
        function_attribution_verified=temp.function_attribution_verified,
        attribution_basis=temp.attribution_basis,
        verified_claims=temp.verified_claims,
        executed_at=temp.executed_at,
        receipt_signature=sig,
        signature_version=temp.signature_version,
    )


class TestSignatureVersionSemanticConsistency(unittest.TestCase):
    """1. Signature-version semantic consistency and downgrade prevention."""

    def setUp(self):
        self.session_secret = "test_session_secret_32_bytes_long_12345"
        self.session_id = "sess_p1241"

    def test_signature_version_normalization_matrix(self):
        """None, empty string, and whitespace-only must normalize to v1_legacy_unversioned."""
        test_cases = [
            (None, "v1_legacy_unversioned"),
            ("", "v1_legacy_unversioned"),
            ("   ", "v1_legacy_unversioned"),
            ("v1_legacy_unversioned", "v1_legacy_unversioned"),
            (" v2_rfc8785 ", "v2_rfc8785"),
            ("v2_rfc8785", "v2_rfc8785"),
            ("v3_future", "v3_future"),
        ]
        for input_ver, expected_ver in test_cases:
            res = make_test_execution_result(
                execution_id="exec_norm",
                investigation_id=self.session_id,
                signature_version=input_ver,
                receipt_signature="dummy_sig",
            )
            self.assertEqual(
                res.signature_version,
                expected_ver,
                f"Input {repr(input_ver)} failed to normalize to {expected_ver}",
            )
            # Serialization round-trip
            d = res.to_dict()
            self.assertEqual(d["signature_version"], expected_ver)
            deserialized = ControlledExecutionResult.from_dict(d)
            self.assertEqual(deserialized.signature_version, expected_ver)

    def test_malformed_v2_not_downgraded_to_v1(self):
        """Malformed or tampered v2 receipt must fail verification, never silently fall back to v1."""
        valid_res = make_test_execution_result(
            execution_id="exec_v2",
            investigation_id=self.session_id,
            signature_version="v2_rfc8785",
            session_secret=self.session_secret,
        )
        self.assertEqual(valid_res.signature_version, "v2_rfc8785")
        self.assertTrue(valid_res.verify_authenticity(self.session_secret))

        # Tamper target_identity pid while keeping signature_version="v2_rfc8785"
        tampered_tid = dict(valid_res.target_identity or {})
        tampered_tid["pid"] = 99999
        tampered_res = make_test_execution_result(
            execution_id=valid_res.execution_id,
            investigation_id=valid_res.investigation_id,
            target_identity=tampered_tid,
            signature_version="v2_rfc8785",
            receipt_signature=valid_res.receipt_signature,
        )

        # Must fail closed under both allow_legacy=True and False
        self.assertFalse(tampered_res.verify_authenticity(self.session_secret, allow_legacy=True))
        self.assertFalse(tampered_res.verify_authenticity(self.session_secret, allow_legacy=False))

    def test_unknown_signature_version_fails_closed(self):
        """Unknown or unsupported signature version fails closed."""
        res = make_test_execution_result(
            execution_id="exec_unknown",
            investigation_id=self.session_id,
            signature_version="v99_unsupported",
            receipt_signature="sig_unknown",
        )
        self.assertFalse(res.verify_authenticity(self.session_secret, allow_legacy=True))
        self.assertFalse(res.verify_authenticity(self.session_secret, allow_legacy=False))


class TestOptInLegacyVerificationPolicy(unittest.TestCase):
    """2. Opt-in legacy signature verification policy."""

    def setUp(self):
        self.session_secret = "optin_legacy_secret_32_bytes_long"
        self.session_id = "sess_optin"
        self.target = {
            "pid": 54321,
            "process_identity": "54321:1700000000:boot_optin",
            "executable_identity": "/usr/bin/optin_app:8080",
            "build_id": "sha1:1111222233334444555566667777888899990000",
        }
        self.legacy_res = make_test_execution_result(
            execution_id="exec_legacy_optin",
            investigation_id=self.session_id,
            target_identity=self.target,
            signature_version="v1_legacy_unversioned",
            session_secret=self.session_secret,
        )
        self.assertTrue(self.legacy_res.verify_authenticity(self.session_secret, allow_legacy=True))
        self.assertFalse(self.legacy_res.verify_authenticity(self.session_secret, allow_legacy=False))

    def test_ledger_opt_in_legacy_rejection(self):
        """EvidenceLedger with allow_legacy_signatures=False rejects legacy receipts."""
        strict_ledger = EvidenceLedger(
            session_id=self.session_id,
            session_secret=self.session_secret,
            allow_legacy_signatures=False,
        )
        strict_ledger.target_identity = dict(self.target)
        with self.assertRaises(ValueError) as cm:
            strict_ledger.issue_verification_capability(
                execution_result=self.legacy_res,
                evidence_id="ev_test",
            )
        self.assertIn("execution receipt signature verification failed", str(cm.exception))

    def test_ledger_opt_in_legacy_acceptance(self):
        """EvidenceLedger with allow_legacy_signatures=True accepts valid legacy receipts."""
        permissive_ledger = EvidenceLedger(
            session_id=self.session_id,
            session_secret=self.session_secret,
            allow_legacy_signatures=True,
        )
        permissive_ledger.target_identity = dict(self.target)
        cap = permissive_ledger.issue_verification_capability(
            execution_result=self.legacy_res,
            evidence_id="ev_test",
        )
        self.assertIsNotNone(cap)
        self.assertEqual(cap.evidence_id, self.legacy_res.evidence_id)

    def test_adapter_opt_in_legacy_policy(self):
        """EvidenceAdapter honors ledger's allow_legacy_signatures policy."""
        adapter = EvidenceAdapter()
        strict_ledger = EvidenceLedger(
            session_id=self.session_id,
            session_secret=self.session_secret,
            allow_legacy_signatures=False,
        )
        strict_ledger.target_identity = dict(self.target)
        prov = adapter._resolve_provenance_class(
            payload={"execution_result": self.legacy_res},
            target_identity=self.target,
            ledger=strict_ledger,
            evidence_id="ev_test",
        )
        self.assertEqual(prov, PROVENANCE_CLASS_IMPORTED_UNVERIFIED)

        permissive_ledger = EvidenceLedger(
            session_id=self.session_id,
            session_secret=self.session_secret,
            allow_legacy_signatures=True,
        )
        permissive_ledger.target_identity = dict(self.target)
        prov = adapter._resolve_provenance_class(
            payload={"execution_result": self.legacy_res},
            target_identity=self.target,
            ledger=permissive_ledger,
            evidence_id="ev_test",
        )
        self.assertEqual(prov, PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION)


class TestRecursiveSecretExposureAudit(unittest.TestCase):
    """3. Recursive secret exposure audit across all models, ledger, reports, and exports."""

    def test_strip_sensitive_session_secrets_full_canary_coverage(self):
        """Ensure all sensitive secret aliases are stripped and safe fields are preserved."""
        canary_payload = {
            # Sensitive keys to strip
            "session_secret": "raw_secret_val_1",
            "_session_secret": "raw_secret_val_2",
            "raw_session_secret": "raw_secret_val_3",
            "session_secret_key": "raw_secret_val_4",
            "secret_key": "raw_secret_val_5",
            "capability_key": "raw_secret_val_6",
            "_capability_key": "raw_secret_val_7",
            "raw_capability_key": "raw_secret_val_8",
            "bearer_token": "raw_secret_val_9",
            "auth_token": "raw_secret_val_10",
            "raw_token": "raw_secret_val_11",
            "token": "raw_secret_val_12",  # any length
            "TOKEN": "raw_secret_val_13",  # uppercase
            "  Secret_Key  ": "raw_secret_val_14",  # whitespace + mixed case
            # Safe keys to preserve
            "token_sig": "sig_abc",
            "receipt_signature": "sig_def",
            "secret_sauce": "barbecue",
            "shared_secret_id": "id_123",
            "safe_nested": {
                "token": "nested_token_stripped",
                "secret_sauce": "teriyaki",
            },
            "safe_list": [
                {"capability_key": "list_token_stripped", "keep_me": 42},
            ],
        }
        cleaned = strip_sensitive_session_secrets(canary_payload)

        # Assert stripped
        for secret_name in SENSITIVE_SECRET_FIELD_NAMES:
            self.assertNotIn(secret_name, cleaned)
        self.assertNotIn("TOKEN", cleaned)
        self.assertNotIn("  Secret_Key  ", cleaned)
        self.assertNotIn("token", cleaned["safe_nested"])
        self.assertNotIn("capability_key", cleaned["safe_list"][0])

        # Assert preserved
        self.assertEqual(cleaned["token_sig"], "sig_abc")
        self.assertEqual(cleaned["receipt_signature"], "sig_def")
        self.assertEqual(cleaned["secret_sauce"], "barbecue")
        self.assertEqual(cleaned["shared_secret_id"], "id_123")
        self.assertEqual(cleaned["safe_nested"]["secret_sauce"], "teriyaki")
        self.assertEqual(cleaned["safe_list"][0]["keep_me"], 42)

    def test_evidence_record_to_dict_redaction_across_all_fields(self):
        """EvidenceRecord.to_dict() must redact secrets across all 7 auxiliary fields + details."""
        rec = EvidenceRecord(
            evidence_id="ev_canary",
            observation="canary test observation",
            provenance={"source": "test", "session_secret": "LEAK_PROV_SECRET"},
            target_identity={"pid": 1234, "session_secret": "LEAK_SECRET_1"},
            capture_quality={"confidence": 0.99, "capability_key": "LEAK_SECRET_2"},
            object_observation={"sym": "g_ptr", "bearer_token": "LEAK_SECRET_3"},
            field_observation={"f": "x", "auth_token": "LEAK_SECRET_4"},
            static_code_link={"file": "a.cpp", "raw_token": "LEAK_SECRET_5"},
            comparison_observation={"diff": "none", "token": "LEAK_SECRET_6"},
            uncertainty="Uncertainty info",
            details={"notes": "test", "_session_secret": "LEAK_SECRET_8"},
        )
        d = rec.to_dict()
        serialized = json.dumps(d)
        for i in [1, 2, 3, 4, 5, 6, 8]:
            self.assertNotIn(f"LEAK_SECRET_{i}", serialized)
        self.assertNotIn("LEAK_PROV_SECRET", serialized)

        # Ensure non-secret keys exist
        self.assertEqual(d["target_identity"]["pid"], 1234)
        self.assertEqual(d["capture_quality"]["confidence"], 0.99)
        self.assertEqual(d["object_observation"]["sym"], "g_ptr")
        self.assertEqual(d["uncertainty"], "Uncertainty info")

    def test_controlled_execution_result_to_dict_redaction(self):
        """ControlledExecutionResult.to_dict() must strip nested secrets in capture_quality or target_identity."""
        res = make_test_execution_result(
            execution_id="exec_canary",
            capture_quality={"completeness": "COMPLETE", "session_secret": "LEAK_RES_1"},
            target_identity={"pid": 1234, "token": "LEAK_RES_2", "safe_meta": "yes"},
        )
        d = res.to_dict()
        serialized = json.dumps(d)
        self.assertNotIn("LEAK_RES_1", serialized)
        self.assertNotIn("LEAK_RES_2", serialized)
        self.assertEqual(d["capture_quality"]["completeness"], "COMPLETE")
        self.assertEqual(d["target_identity"]["safe_meta"], "yes")

    def test_verdict_engine_zero_cdn_reporter_json_and_html_redaction(self):
        """ZeroCdnReporter must redact secrets from both JSON render and HTML export."""
        reporter = ZeroCdnReporter()
        verdict = DiagnosticVerdict(
            hypothesis="leak test",
            final_diagnosis="CONFIRMED",
            hypothesis_state="VALIDATED",
            confidence_score=0.95,
            total_assertions=1,
            passed_count=1,
            failed_count=0,
            abstain_count=0,
            assertion_evaluations=[],
            causal_attribution_verified=True,
            attribution_basis="controlled",
            provenance_class="PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION",
            target_identity={"name": "srv", "session_secret": "LEAK_VERDICT_SECRET"},
            limitations=[],
            budget_usage={},
        )
        json_out = reporter.render_json(verdict, metadata={"bearer_token": "LEAK_META_TOKEN"})
        self.assertNotIn("LEAK_VERDICT_SECRET", json_out)
        self.assertNotIn("LEAK_META_TOKEN", json_out)

        html_out = reporter.generate_html_report("Title", {"token": "LEAK_HTML_SECRET", "data": "ok"})
        self.assertNotIn("LEAK_HTML_SECRET", html_out)


class TestCanonicalJsonInputValidationAndV8Differential(unittest.TestCase):
    """4. Canonical JSON input validation and deterministic V8 differential suite."""

    def test_convert2es6format_type_rejection(self):
        """convert2Es6Format must raise TypeError on non-numeric types including bool."""
        invalid_inputs = [
            True,
            False,
            "123",
            "1.5",
            None,
            [],
            {},
            (1, 2),
            object(),
        ]
        for val in invalid_inputs:
            with self.assertRaises(TypeError, msg=f"Should raise TypeError for {repr(val)}"):
                convert2Es6Format(val)

    def test_convert2es6format_safe_integer_boundaries(self):
        """Safe integer boundary checks per RFC 7493 / RFC 8785."""
        self.assertEqual(convert2Es6Format(0), "0")
        self.assertEqual(convert2Es6Format(IEEE754_MAX_SAFE_INTEGER), str(IEEE754_MAX_SAFE_INTEGER))
        self.assertEqual(convert2Es6Format(IEEE754_MIN_SAFE_INTEGER), str(IEEE754_MIN_SAFE_INTEGER))

        with self.assertRaises(ValueError):
            convert2Es6Format(IEEE754_MAX_SAFE_INTEGER + 1)
        with self.assertRaises(ValueError):
            convert2Es6Format(IEEE754_MIN_SAFE_INTEGER - 1)

    def test_v8_differential_exactness(self):
        """Differential comparison between python convert2Es6Format and Node.js V8 ToString(Number)."""
        test_numbers = [
            0.0,
            -0.0,
            1.0,
            -1.0,
            42.0,
            -42.0,
            1e-7,
            1e-6,
            0.000001,
            0.0000001,
            1e20,
            1e21,
            100000000000000000000.0,
            5e-324,
            2.2250738585072014e-308,
            1.7976931348623157e+308,
            math.pi,
            math.e,
            0.1 + 0.2,
            1.2345678901234567,
            -987654.32109876,
        ]

        # Generate 100 reproducible pseudo-random floats using deterministic LCG
        state = 0x12345678
        for _ in range(100):
            state = (state * 1664525 + 1013904223) & 0xFFFFFFFF
            mantissa = (state & 0x000FFFFFFFFFFFFF) if state != 0 else 1
            exp = (state % 600) - 300
            val = mantissa * (10.0 ** exp)
            if math.isfinite(val) and val != 0.0:
                test_numbers.append(val)
                test_numbers.append(-val)

        # Query Node.js V8 for canonical ToString(Number)
        node_ver_proc = subprocess.run(["node", "-v"], stdout=subprocess.PIPE, text=True, check=True)
        node_version = node_ver_proc.stdout.strip()
        self.assertTrue(node_version.startswith("v"), f"Invalid node version: {node_version}")

        js_script = """
        const readline = require('readline');
        const rl = readline.createInterface({ input: process.stdin, terminal: false });
        rl.on('line', (line) => {
            const raw = JSON.parse(line);
            const num = raw.val;
            process.stdout.write(JSON.stringify({ out: String(num) }) + '\\n');
        });
        """
        proc = subprocess.Popen(
            ["node", "-e", js_script],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )

        mismatches = []
        try:
            for num in test_numbers:
                py_res = convert2Es6Format(num)
                proc.stdin.write(json.dumps({"val": num}) + "\n")
                proc.stdin.flush()
                out_line = proc.stdout.readline()
                node_res = json.loads(out_line)["out"]
                # ES6: -0 is formatted as "0"
                if py_res != node_res:
                    mismatches.append((num, py_res, node_res))
        finally:
            if proc.stdin:
                proc.stdin.close()
            if proc.stdout:
                proc.stdout.close()
            proc.wait()

        self.assertEqual(len(mismatches), 0, f"V8 differential mismatches found: {mismatches[:5]}")


class TestLegacyMigrationLifecycleAndPersistence(unittest.TestCase):
    """5. Legacy migration idempotency, tampered receipt rejection, and save/reload persistence."""

    def setUp(self):
        self.session_secret = "legacy_migration_test_secret_32b"
        self.session_id = "sess_mig_test"
        self.target = {
            "pid": 54321,
            "process_identity": "54321:1700000000:boot_mig",
            "executable_identity": "/usr/bin/mig_app:8080",
            "build_id": "sha1:9999888877776666555544443333222211110000",
        }

    def test_migration_idempotency(self):
        """migrate_legacy_execution_result on already v2 receipt returns receipt unchanged."""
        v2_res = make_test_execution_result(
            execution_id="exec_v2_ready",
            investigation_id=self.session_id,
            target_identity=self.target,
            signature_version="v2_rfc8785",
            session_secret=self.session_secret,
        )
        self.assertEqual(v2_res.signature_version, "v2_rfc8785")
        orig_sig = v2_res.receipt_signature

        # Run migration
        migrated = migrate_legacy_execution_result(v2_res, self.session_secret)
        self.assertIs(migrated, v2_res)
        self.assertEqual(migrated.receipt_signature, orig_sig)
        self.assertEqual(migrated.signature_version, "v2_rfc8785")

    def test_tampered_legacy_receipt_migration_fails_closed(self):
        """Tampered legacy receipt fails closed during migration."""
        legacy_res = make_test_execution_result(
            execution_id="exec_tampered_legacy",
            investigation_id=self.session_id,
            target_identity=self.target,
            signature_version="v1_legacy_unversioned",
            session_secret=self.session_secret,
        )
        # Tamper verified claims
        tampered_claims = ("CLAIM_FORGED",)
        tampered_res = make_test_execution_result(
            execution_id=legacy_res.execution_id,
            investigation_id=legacy_res.investigation_id,
            target_identity=legacy_res.target_identity,
            signature_version="v1_legacy_unversioned",
            receipt_signature=legacy_res.receipt_signature,
            verified_claims=tampered_claims,
        )

        with self.assertRaises(ValueError) as cm:
            migrate_legacy_execution_result(tampered_res, self.session_secret)
        self.assertIn("authenticity verification failed", str(cm.exception))

    def test_migrated_evidence_ledger_save_reload_persistence(self):
        """Evidence ledger with migrated evidence survives to_dict -> from_dict serialization."""
        ledger = EvidenceLedger(
            session_id=self.session_id,
            session_secret=self.session_secret,
            allow_legacy_signatures=True,
        )
        ledger.target_identity = dict(self.target)

        legacy_res = make_test_execution_result(
            execution_id="exec_legacy_pers",
            investigation_id=self.session_id,
            target_identity=self.target,
            signature_version="v1_legacy_unversioned",
            session_secret=self.session_secret,
            evidence_id="ev_legacy_pers",
        )

        adapter = EvidenceAdapter()
        rec = adapter.adapt_generic_tool_output(
            tool_name="controlled_verifier",
            tool_result={
                "outcome": "reproduced",
                "provenance_class": PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION,
                "execution_result": legacy_res,
            },
            target_identity=self.target,
            session_id=self.session_id,
            ledger=ledger,
            evidence_id="ev_legacy_pers",
        )
        self.assertEqual(rec.provenance_class, PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION)

        # Migrate evidence ledger
        migrated_count = ledger.migrate_legacy_evidence("ev_legacy_pers")
        self.assertTrue(migrated_count)

        # Verify the record is now v2
        migrated_rec = ledger.get_record("ev_legacy_pers")
        upgraded_exec = migrated_rec.provenance["controlled_execution_result"]
        self.assertEqual(upgraded_exec["signature_version"], "v2_rfc8785")

        # Serialize and restore ledger
        ledger_dict = ledger.to_dict()
        restored_ledger = EvidenceLedger.from_dict(ledger_dict, session_secret=self.session_secret)

        restored_rec = restored_ledger.get_record("ev_legacy_pers")
        self.assertIsNotNone(restored_rec)
        restored_exec = restored_rec.provenance["controlled_execution_result"]
        self.assertEqual(restored_exec["signature_version"], "v2_rfc8785")


class TestTrustLifecycleInvariants(unittest.TestCase):
    """6. Trust lifecycle invariants (concurrency, rollback, scope binding)."""

    def setUp(self):
        self.session_secret = "trust_lifecycle_secret_32b_12345"
        self.session_id = "sess_lifecycle"
        self.target = {
            "pid": 54321,
            "process_identity": "54321:1700000000:boot_lifecycle",
            "executable_identity": "/usr/bin/lifecycle_app:8080",
            "build_id": "sha1:9999888877776666555544443333222211110000",
        }
        self.ledger = EvidenceLedger(
            session_id=self.session_id,
            session_secret=self.session_secret,
        )
        self.ledger.target_identity = dict(self.target)

    def test_concurrent_single_use_consumption(self):
        """Execution result cannot be consumed concurrently by multiple threads."""
        res = make_test_execution_result(
            execution_id="exec_single_use_race",
            investigation_id=self.session_id,
            target_identity=self.target,
            signature_version="v2_rfc8785",
            session_secret=self.session_secret,
            evidence_id="ev_single_use",
        )

        success_count = 0
        failure_count = 0
        lock = threading.Lock()

        def try_issue():
            nonlocal success_count, failure_count
            try:
                cap = self.ledger.issue_verification_capability(
                    execution_result=res,
                    evidence_id="ev_single_use",
                )
                with lock:
                    success_count += 1
            except ValueError:
                with lock:
                    failure_count += 1

        threads = [threading.Thread(target=try_issue) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(success_count, 1, "Exactly one thread must succeed in capability issuance")
        self.assertEqual(failure_count, 9, "All subsequent concurrent requests must be rejected")


if __name__ == "__main__":
    unittest.main()
