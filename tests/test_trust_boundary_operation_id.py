"""Unit tests for Operation ID validation and trust boundary preconditions.

Verifies:
1. Strict whitelist regex: ^[a-zA-Z0-9_.:-]{1,128}$
2. Rejection of None, empty string, whitespace-only, and unicode characters.
3. No silent trimming or normalization (leading/trailing whitespace must fail).
4. Validation order: DurableTrustStore and Attestation consumption must validate
   operation_id before touching durable trust store state or disk.
"""

import os
import tempfile
import unittest

from extractor.capture_backend import (
    CausalAttestation,
    DurableTrustStore,
    InvalidOperationIdError,
    validate_operation_id,
)


class TestTrustBoundaryOperationId(unittest.TestCase):
    """Regression test suite for Operation ID trust boundary."""

    def test_valid_operation_ids_accepted(self):
        """Valid format strings must pass validation unchanged."""
        valid_samples = [
            "op-1234",
            "operation_id_test",
            "run.2026-11-15:session-01",
            "OP_123.456-789:abc",
            "a" * 128,  # Exactly 128 characters
            "1",
        ]
        for sample in valid_samples:
            result = validate_operation_id(sample)
            self.assertEqual(result, sample)

    def test_invalid_types_and_empty_rejected(self):
        """None, empty, or non-string inputs must raise InvalidOperationIdError."""
        invalid_samples = [
            None,
            "",
            12345,
            ["op-123"],
            {"id": "op-123"},
        ]
        for sample in invalid_samples:
            with self.assertRaises(InvalidOperationIdError):
                validate_operation_id(sample)

    def test_whitespace_and_trim_rejection(self):
        """Whitespace-only, leading, or trailing whitespace must fail without silent trimming."""
        whitespace_samples = [
            "   ",
            " op-123",
            "op-123 ",
            " op-123 ",
            "\top-123",
            "op-123\n",
        ]
        for sample in whitespace_samples:
            with self.assertRaises(InvalidOperationIdError):
                validate_operation_id(sample)

    def test_invalid_characters_and_unicode_rejected(self):
        """Path traversal characters, control chars, and unicode symbols must fail."""
        invalid_char_samples = [
            "op/123",  # slash
            "op\\123",  # backslash
            "op;123",  # semicolon
            "op$123",  # dollar
            "op`123",  # backtick
            "op—123",  # unicode em-dash
            "op１２３",  # full-width unicode numbers
            "op\x00123",  # null byte
            "a" * 129,  # 129 characters (exceeds 128 max length)
        ]
        for sample in invalid_char_samples:
            with self.assertRaises(InvalidOperationIdError):
                validate_operation_id(sample)

    def test_consume_attestation_enforces_operation_id_validation(self):
        """DurableTrustStore.consume_attestation must validate operation_id before durable commit."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store_path = os.path.join(tmpdir, "trust_store.json")
            store = DurableTrustStore(store_path=store_path)

            att = CausalAttestation(
                attestation_id="att-valid-01",
                session_id="sess-01",
                target_identity={"pid": 12345, "boot_id": "boot-test"},
                operation_id="op-valid-01",
                precondition_evidence_id="pre-01",
                postcondition_evidence_id="post-01",
                key_id="default",
                issued_at_ns=1000,
                expires_at_ns=2000,
            )

            # Invalid operation_id must raise InvalidOperationIdError before modifying store
            with self.assertRaises(InvalidOperationIdError):
                store.consume_attestation(
                    attestation=att,
                    evidence_id="ev-01",
                    operation_id=" invalid op id ",  # contains whitespace
                )

            # Trust store file should either not exist or not have recorded this attestation
            self.assertFalse(store.is_attestation_used("att-valid-01"))


if __name__ == "__main__":
    unittest.main()
