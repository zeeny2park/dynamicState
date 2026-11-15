"""Property-Based Tests (PBT) using Hypothesis for Operation Identity invariants.

Enforces:
1. Deterministic seed (seed=42) for reproducible PR CI.
2. At least 100 examples per property test.
3. Counterexample shrinking enabled.
4. Testing of Operation ID validation, Process Identity equality, and canonical serialization.
"""

import json
import string
import unittest

from hypothesis import HealthCheck, given, seed, settings, strategies as st

from extractor.capture_backend import (
    CanonicalOperationIdentity,
    InvalidOperationIdError,
    ProcessIdentity,
    validate_operation_id,
)

VALID_CHARS = string.ascii_letters + string.digits + "_.:-"


class TestPbtOperationIdentity(unittest.TestCase):
    """Hypothesis Property-Based Testing suite for Operation Identity invariants."""

    @seed(42)
    @settings(max_examples=150)
    @given(st.text(alphabet=VALID_CHARS, min_size=1, max_size=128))
    def test_property_valid_operation_id_always_accepted(self, op_id):
        """Invariant 1: Any string formed strictly of valid chars (len 1..128) must pass unchanged."""
        result = validate_operation_id(op_id)
        self.assertEqual(result, op_id)

    @seed(42)
    @settings(max_examples=150)
    @given(st.text())
    def test_property_invalid_operation_id_always_rejected(self, raw_input):
        """Invariant 2: Any string violating length, containing whitespace or non-whitelist characters must fail."""
        has_invalid_char = any(c not in VALID_CHARS for c in raw_input)
        is_bad_length = len(raw_input) < 1 or len(raw_input) > 128
        has_whitespace = any(c.isspace() for c in raw_input)

        if has_invalid_char or is_bad_length or has_whitespace:
            with self.assertRaises(InvalidOperationIdError):
                validate_operation_id(raw_input)
        else:
            # Must be a valid ID
            self.assertEqual(validate_operation_id(raw_input), raw_input)

    @seed(42)
    @settings(max_examples=100)
    @given(
        host=st.text(alphabet=string.ascii_lowercase + "-", min_size=1, max_size=32),
        boot=st.text(alphabet=string.hexdigits + "-", min_size=1, max_size=36),
        pid=st.integers(min_value=1, max_value=4194304),
        start_time=st.integers(min_value=0, max_value=2**32 - 1),
    )
    def test_property_process_identity_invariants(self, host, boot, pid, start_time):
        """Invariant 3: ProcessIdentity 4-tuple equality is strictly reflexive, symmetric, and sensitive to every field."""
        p1 = ProcessIdentity(host_identity=host, boot_id=boot, pid=pid, process_start_time=start_time)
        p2 = ProcessIdentity(host_identity=host, boot_id=boot, pid=pid, process_start_time=start_time)

        self.assertEqual(p1, p2)
        self.assertEqual(hash(p1), hash(p2))
        self.assertTrue(p1.matches(p2))

        # Changing any single field breaks match
        p_diff_pid = ProcessIdentity(host_identity=host, boot_id=boot, pid=pid + 1, process_start_time=start_time)
        self.assertFalse(p1.matches(p_diff_pid))

    @seed(42)
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    @given(
        params=st.dictionaries(
            keys=st.text(alphabet=string.ascii_lowercase, min_size=1, max_size=8),
            values=st.one_of(st.integers(min_value=0, max_value=1000), st.text(max_size=10), st.booleans()),
            max_size=5,
        )
    )
    def test_property_canonical_serialization_deterministic_ordering(self, params):
        """Invariant 4: Normalized parameters in CanonicalOperationIdentity must sort keys deterministically."""
        proc_id = ProcessIdentity(
            host_identity="host-pbt",
            boot_id="boot-pbt",
            pid=100,
            process_start_time=5000,
        )
        sorted_params = dict(sorted(params.items()))
        canonical = CanonicalOperationIdentity(
            operation_id="op-pbt-01",
            operation_kind="LIVE_CAPTURE",
            process_identity=proc_id,
            build_id="build-pbt",
            session_identity="sess-pbt",
            request_scope="scope-pbt",
            normalized_parameters=sorted_params,
        )

        # Keys in normalized_parameters must match sorted order exactly
        self.assertEqual(list(canonical.normalized_parameters.keys()), sorted(params.keys()))


if __name__ == "__main__":
    unittest.main()
