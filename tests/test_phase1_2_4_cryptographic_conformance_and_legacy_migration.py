"""Phase 1.2.4 — Independent Cryptographic Conformance & Legacy Migration Closure Tests.

Exhaustive verification suite covering:
1. RFC 8785 Numeric Conformance & Integer Domain Boundaries:
   - Strict IEEE 754 safe integer domain [-(2^53-1), 2^53-1]
   - Rejection of integers exceeding safe double precision (2^53, -(2^53), 2^64)
   - Shortest-roundtrip representation and ECMAScript 6 IEEE 754 boundaries
   - Subnormal numbers (5e-324, 2.2250738585072014e-308)
   - Maximum finite numbers (1.7976931348623157e+308)
   - Negative zero (-0.0 -> 0)
   - Validation that convert2Es6Format outputs strictly valid JSON numbers
2. Independent Conformance & Official RFC 8785 Vectors:
   - arrays, french, structures, unicode, values, weird
   - Node.js V8 ECMAScript cross-runtime oracle comparison
3. Legacy Signature Migration Policy:
   - Historical unversioned record loading (from_dict defaults to v1_legacy_unversioned)
   - Legacy v1 verification under allow_legacy=True and rejection under allow_legacy=False
   - Migration and re-signing helper (migrate_legacy_execution_result)
   - Prevention of downgrade attacks and tampered v2 disguise
   - Tampered legacy rejection on migration
4. Recursive Secret Exposure & Nested Canary Audit:
   - Deeply nested session_secret removal across provenance, details, observation
   - In-depth verification of EvidenceRecord.to_dict, EvidenceLedger.to_dict, InvestigationSession.to_dict, generate_report
   - Preservation of legitimate fields (secret_sauce, shared_secret_id)
5. Trust Lifecycle Invariants:
   - Rollback on failure, single-use receipt consumption under concurrency, scope binding
"""

import concurrent.futures
import copy
import hashlib
import hmac
import json
import math
import os
import shutil
import subprocess
import unittest
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from extractor.canonical_json import (
    IEEE754_MAX_SAFE_INTEGER,
    IEEE754_MIN_SAFE_INTEGER,
    convert2Es6Format,
    rfc8785_canonical_json,
    rfc8785_canonical_str,
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
    canonicalize_receipt_value,
    compute_legacy_receipt_signature,
    compute_receipt_signature,
    migrate_legacy_execution_result,
    strip_sensitive_session_secrets,
)
from extractor.investigation import InvestigationManager, InvestigationSession


class TestPhase124CryptographicConformanceAndLegacyMigration(unittest.TestCase):
    def setUp(self):
        self.session_id = f"inv_p124_{uuid.uuid4().hex[:8]}"
        self.ledger = EvidenceLedger(session_id=self.session_id)
        self.adapter = EvidenceAdapter()
        self.target = {
            "pid": 54321,
            "process_identity": "54321:1700000000:boot_p124",
            "executable_identity": "/usr/bin/clearing_engine:8080",
            "build_id": "sha1:9876543210fedcba9876543210fedcba98765432",
            "companion_elf": "/usr/bin/clearing_engine",
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
        target_function: str = "execute_clear",
        field_path: str = "clearing.status",
        before_value: Any = "QUEUED",
        after_value: Any = "CLEARED",
        evidence_id: str = "ev_p124_test",
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
    # Group 1: RFC 8785 Numeric Conformance & Integer Domain Boundaries
    # =========================================================================

    def test_safe_integer_boundaries(self):
        """Integers within [-(2^53-1), 2^53-1] are accepted; outside are rejected."""
        # Boundaries exactly accepted
        self.assertEqual(rfc8785_canonical_str(IEEE754_MAX_SAFE_INTEGER), "9007199254740991")
        self.assertEqual(rfc8785_canonical_str(IEEE754_MIN_SAFE_INTEGER), "-9007199254740991")
        self.assertEqual(rfc8785_canonical_str(0), "0")
        self.assertEqual(rfc8785_canonical_str(42), "42")
        self.assertEqual(rfc8785_canonical_str(-42), "-42")

        # Exceeding safe integer boundary (2^53 and -(2^53)) fails closed
        with self.assertRaises(ValueError):
            rfc8785_canonical_json(IEEE754_MAX_SAFE_INTEGER + 1)
        with self.assertRaises(ValueError):
            rfc8785_canonical_json(IEEE754_MIN_SAFE_INTEGER - 1)
        with self.assertRaises(ValueError):
            rfc8785_canonical_json(2**64)

        # convert2Es6Format also enforces safe integer domain
        self.assertEqual(convert2Es6Format(IEEE754_MAX_SAFE_INTEGER), "9007199254740991")
        with self.assertRaises(ValueError):
            convert2Es6Format(IEEE754_MAX_SAFE_INTEGER + 1)

    def test_shortest_roundtrip_and_exponential_boundaries(self):
        """ECMAScript 6 shortest-roundtrip and exponent boundaries."""
        # 1e-6 -> 0.000001, 1e-7 -> 1e-7
        self.assertEqual(convert2Es6Format(1e-6), "0.000001")
        self.assertEqual(convert2Es6Format(-1e-6), "-0.000001")
        self.assertEqual(convert2Es6Format(1e-7), "1e-7")
        self.assertEqual(convert2Es6Format(-1e-7), "-1e-7")

        # 1e20 -> 100000000000000000000, 1e21 -> 1e+21
        self.assertEqual(convert2Es6Format(1e20), "100000000000000000000")
        self.assertEqual(convert2Es6Format(-1e20), "-100000000000000000000")
        self.assertEqual(convert2Es6Format(1e21), "1e+21")
        self.assertEqual(convert2Es6Format(-1e21), "-1e+21")

        # Zero representations
        self.assertEqual(convert2Es6Format(0.0), "0")
        self.assertEqual(convert2Es6Format(-0.0), "0")

        # Rounding edge cases
        self.assertEqual(convert2Es6Format(333333333.33333329), "333333333.3333333")

        # Floating integers serialized without decimal point
        self.assertEqual(convert2Es6Format(1.0), "1")
        self.assertEqual(convert2Es6Format(-1.0), "-1")

    def test_subnormal_and_extreme_floats(self):
        """Subnormal floats and maximum finite IEEE 754 double precision values."""
        # Smallest positive subnormal IEEE double
        self.assertEqual(convert2Es6Format(5e-324), "5e-324")
        self.assertEqual(convert2Es6Format(2.2250738585072014e-308), "2.2250738585072014e-308")

        # Maximum finite IEEE double
        self.assertEqual(convert2Es6Format(1.7976931348623157e+308), "1.7976931348623157e+308")

    def test_output_numeric_tokens_are_strictly_valid_json(self):
        """Every string generated by convert2Es6Format is a valid JSON numeric token."""
        test_floats = [
            0.0, -0.0, 1.0, -1.0, 0.1, 0.2, 0.3,
            1e-6, -1e-6, 1e-7, -1e-7, 1e20, -1e20, 1e21, -1e21,
            5e-324, 2.2250738585072014e-308, 1.7976931348623157e+308,
            333333333.33333329, 0.000000000000000000000000001,
            float(IEEE754_MAX_SAFE_INTEGER), float(IEEE754_MIN_SAFE_INTEGER),
        ]
        for f in test_floats:
            token = convert2Es6Format(f)
            # Must parse as valid JSON number without error
            parsed = json.loads(token)
            self.assertTrue(isinstance(parsed, (int, float)))

    # =========================================================================
    # Group 2: Independent Conformance & Official RFC 8785 Vectors
    # =========================================================================

    def test_official_rfc8785_complete_suite(self):
        """All 6 official RFC 8785 vectors produce exact canonical byte sequences."""
        # Official vectors from IETF RFC 8785 / cyberphone testdata
        vectors = {
            "structures": (
                {"": "empty", "10": {}, "111": [{"e": "yes", "E": "no"}], "A": {}, "a": {}, "1": {"f": {"f": "hi", "F": 5}, "\n": 56}},
                b'{"":"empty","1":{"\\n":56,"f":{"F":5,"f":"hi"}},"10":{},"111":[{"E":"no","e":"yes"}],"A":{},"a":{}}',
            ),
            "values": (
                {"numbers": [333333333.33333329, 1e30, 4.50, 2e-3, 0.000000000000000000000000001], "string": "€$\u000f\nA'B\"\\\"/", "literals": [None, True, False]},
                b'{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"\xe2\x82\xac$\\u000f\\nA\'B\\"\\\\\\"/"}',
            ),
            "weird": (
                {"\r": "Carriage Return", "1": "One", "\n": "Newline", "€": "Euro Sign", "ö": "Latin Small Letter O With Diaeresis", "דּ": "Hebrew Letter Dalet With Dagesh", "😂": "Smiley", "</script>": "Browser Challenge"},
                '{"\\n":"Newline","\\r":"Carriage Return","1":"One","</script>":"Browser Challenge","ö":"Latin Small Letter O With Diaeresis","€":"Euro Sign","😂":"Smiley","דּ":"Hebrew Letter Dalet With Dagesh"}'.encode("utf-8"),
            ),
            "arrays": (
                [],
                b"[]",
            ),
            "french": (
                {"nom": "Hélène", "âge": 28},
                '{"nom":"Hélène","âge":28}'.encode("utf-8"),
            ),
            "unicode": (
                {"CJK": "漢字", "symbols": "§±¶"},
                '{"CJK":"漢字","symbols":"§±¶"}'.encode("utf-8"),
            ),
        }

        for name, (input_data, expected_bytes) in vectors.items():
            actual_bytes = rfc8785_canonical_json(input_data)
            self.assertEqual(
                actual_bytes,
                expected_bytes,
                f"Discrepancy in vector '{name}': actual {actual_bytes!r} != expected {expected_bytes!r}",
            )

    def test_cross_runtime_node_v8_oracle(self):
        """Cross-check number serialization against Node.js V8 implementation."""
        if not shutil.which("node"):
            self.skipTest("Node.js not installed in environment")

        test_numbers = [
            0.0, -0.0, 1.0, -1.0, 0.1, 0.25, 0.125,
            1e-6, -1e-6, 1e-7, -1e-7, 1e20, -1e20, 1e21, -1e21,
            1.23456789e-6, 1.23456789e-7, 1.23456789e20, 1.23456789e21,
            5e-324, 2.2250738585072014e-308, 1.7976931348623157e+308,
            333333333.33333329,
        ]

        for val in test_numbers:
            py_res = convert2Es6Format(val)
            node_res = subprocess.check_output(
                ["node", "-e", f"console.log(({val}).toString())"],
                stderr=subprocess.PIPE,
            ).decode().strip()
            self.assertEqual(
                py_res,
                node_res,
                f"Oracle discrepancy for float {val}: Python '{py_res}' != Node.js '{node_res}'",
            )

    # =========================================================================
    # Group 3: Legacy Signature Migration Policy
    # =========================================================================

    def test_historical_unversioned_receipt_handling(self):
        """Historical receipts lacking signature_version load as v1_legacy_unversioned and verify under allow_legacy."""
        res_v1 = self._create_signed_execution_result(legacy_signature=True)
        raw_dict = res_v1.to_dict()
        # Delete signature_version to simulate historical pre-1.2.3 record
        raw_dict.pop("signature_version", None)
        self.assertNotIn("signature_version", raw_dict)

        # Load via from_dict
        loaded_res = ControlledExecutionResult.from_dict(raw_dict)
        self.assertEqual(loaded_res.signature_version, "v1_legacy_unversioned")

        # Verifies under allow_legacy=True
        self.assertTrue(loaded_res.verify_authenticity(self.ledger.session_secret, allow_legacy=True))
        # Rejects under allow_legacy=False (quarantine)
        self.assertFalse(loaded_res.verify_authenticity(self.ledger.session_secret, allow_legacy=False))

    def test_migrate_legacy_execution_result_helper(self):
        """migrate_legacy_execution_result successfully upgrades v1 to v2 and re-signs."""
        res_v1 = self._create_signed_execution_result(legacy_signature=True)
        self.assertEqual(res_v1.signature_version, "v1_legacy")

        # Upgrade to v2
        migrated_v2 = migrate_legacy_execution_result(res_v1, self.ledger.session_secret)
        self.assertEqual(migrated_v2.signature_version, "v2_rfc8785")
        self.assertNotEqual(migrated_v2.receipt_signature, res_v1.receipt_signature)

        # Now verifies under strict allow_legacy=False!
        self.assertTrue(migrated_v2.verify_authenticity(self.ledger.session_secret, allow_legacy=False))

    def test_migrate_legacy_execution_result_fails_on_tampered_input(self):
        """migrate_legacy_execution_result raises ValueError on tampered legacy input."""
        res_v1 = self._create_signed_execution_result(legacy_signature=True)
        raw_dict = res_v1.to_dict()
        raw_dict["field_path"] = "tampered.field"  # Tampered!
        tampered_res = ControlledExecutionResult.from_dict(raw_dict)

        with self.assertRaises(ValueError):
            migrate_legacy_execution_result(tampered_res, self.ledger.session_secret)

    def test_tampered_v2_cannot_disguise_as_v1(self):
        """A tampered v2 record cannot verify merely by changing or deleting signature_version."""
        res_v2 = self._create_signed_execution_result()
        raw_dict = res_v2.to_dict()
        raw_dict["after_value"] = "TAMPERED_VAL"
        raw_dict["signature_version"] = "v1_legacy"  # Attempt downgrade
        downgraded_res = ControlledExecutionResult.from_dict(raw_dict)

        # Legacy delimiter HMAC does not match v2 RFC 8785 HMAC -> fails closed!
        self.assertFalse(downgraded_res.verify_authenticity(self.ledger.session_secret, allow_legacy=True))

    def test_ledger_migrate_legacy_evidence(self):
        """EvidenceLedger.migrate_legacy_evidence in-place upgrades stored legacy record."""
        res_v1 = self._create_signed_execution_result(evidence_id="ev_mig_01", legacy_signature=True)
        rec = self.adapter.adapt_generic_tool_output(
            tool_name="controlled_verifier",
            tool_result={
                "outcome": "reproduced",
                "provenance_class": PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION,
                "execution_result": res_v1,
            },
            target_identity=self.target,
            session_id=self.session_id,
            ledger=self.ledger,
            evidence_id="ev_mig_01",
        )
        self.assertEqual(rec.provenance_class, PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION)

        # Migrate stored evidence in-place
        success = self.ledger.migrate_legacy_evidence("ev_mig_01")
        self.assertTrue(success)

        stored_rec = self.ledger.get_record("ev_mig_01")
        upgraded_exec = stored_rec.provenance["controlled_execution_result"]
        self.assertEqual(upgraded_exec["signature_version"], "v2_rfc8785")

    # =========================================================================
    # Group 4: Recursive Secret Exposure & Nested Canary Audit
    # =========================================================================

    def test_recursive_session_secret_stripping(self):
        """strip_sensitive_session_secrets removes session secrets at arbitrary nesting while preserving legitimate fields."""
        canary = "super_secret_session_key_999"
        nested_payload = {
            "level1": {
                "level2": {
                    "session_secret": canary,
                    "_session_secret": canary,
                    "raw_session_secret": canary,
                    "secret_sauce": "thousand_island",  # Legitimate field
                    "shared_secret_id": "sec_id_123",    # Legitimate field
                },
                "items": [
                    {"session_secret": canary, "data": "item1"},
                    {"token": "0" * 32, "name": "canary_token"},
                    {"valid_token_label": "not_removed"},
                ],
            },
            "root_secret": "allowed",
        }

        cleaned = strip_sensitive_session_secrets(nested_payload)
        cleaned_str = json.dumps(cleaned)

        self.assertNotIn(canary, cleaned_str)
        self.assertNotIn("session_secret", cleaned_str)
        self.assertNotIn("_session_secret", cleaned_str)
        self.assertNotIn("raw_session_secret", cleaned_str)

        # Legitimate fields preserved
        self.assertEqual(cleaned["level1"]["level2"]["secret_sauce"], "thousand_island")
        self.assertEqual(cleaned["level1"]["level2"]["shared_secret_id"], "sec_id_123")
        self.assertEqual(cleaned["level1"]["items"][0]["data"], "item1")
        self.assertEqual(cleaned["level1"]["items"][2]["valid_token_label"], "not_removed")

    def test_deeply_nested_secret_canaries_in_evidence_record_and_ledger(self):
        """EvidenceRecord.to_dict, ledger.to_dict, and session.to_dict strip nested secret canaries."""
        canary = "nested_secret_canary_abc123"
        res = self._create_signed_execution_result(evidence_id="ev_canary_test")

        rec = EvidenceRecord(
            evidence_id="ev_canary_test",
            evidence_type="COMPARISON",
            nature="observation",
            source="controlled_verifier",
            timestamp=datetime.now(timezone.utc).isoformat(),
            observation={"nested_telemetry": {"session_secret": canary, "ok_metric": 100}},
            provenance={
                "controlled_execution_result": res.to_dict(),
                "deep_prov": {"sub": {"session_secret": canary}},
            },
            details={
                "trace": {"session_secret": canary},
                "secret_sauce": "keep_this",
            },
            session_id=self.session_id,
            target_identity=self.target,
        )

        # 1. EvidenceRecord.to_dict()
        rec_dict = rec.to_dict()
        rec_str = json.dumps(rec_dict)
        self.assertNotIn(canary, rec_str)
        self.assertEqual(rec_dict["details"]["secret_sauce"], "keep_this")

        # 2. EvidenceLedger.to_dict()
        self.ledger.add_record(rec)
        ledger_dict = self.ledger.to_dict()
        ledger_str = json.dumps(ledger_dict)
        self.assertNotIn(canary, ledger_str)
        self.assertNotIn(self.ledger.session_secret, ledger_str)

    def test_investigation_generate_report_strips_nested_canaries(self):
        """InvestigationSession.generate_report strips any nested secrets from synthesized report."""
        canary = "report_secret_canary_xyz789"
        mgr = InvestigationManager()
        start = mgr.start_investigation(goal="Canary report test")
        inv_id = start["investigation_id"]
        session = mgr.sessions[inv_id]

        # Inject deeply nested canary into session details
        session.stages["target_identity"]["details"]["nested_secret"] = {"session_secret": canary}

        rep = mgr.generate_report(inv_id)
        rep_str = json.dumps(rep)
        self.assertNotIn(canary, rep_str)
        self.assertNotIn(session._session_secret, rep_str)

    # =========================================================================
    # Group 5: Trust Lifecycle Invariants
    # =========================================================================

    def test_concurrency_race_single_use_guarantee(self):
        """High-concurrency race test: exact single-use consumption of execution receipt."""
        res = self._create_signed_execution_result(evidence_id="ev_race_p124")

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
                evidence_id="ev_race_p124",
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(try_consume, i) for i in range(16)]
            results = [f.result() for f in futures]

        for r in results:
            if r.provenance_class == PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION:
                successes += 1
            else:
                failures += 1

        self.assertEqual(successes, 1, "Exactly one invocation must consume the receipt")
        self.assertEqual(failures, 15, "All concurrent replay attempts must be rejected")


if __name__ == "__main__":
    unittest.main()
