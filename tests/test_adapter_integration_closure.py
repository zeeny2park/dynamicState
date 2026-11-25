"""Integration tests for Adapter Architecture Integration & Identity Policy Closure.

Exercises real end-to-end paths:
- Adapter.get_identity_policy() -> CaptureTransaction -> physical read ->
  commit_capture_transaction -> issue_live_capture_receipt -> DurableTrustStore
  -> LiveCaptureReceipt.verify() -> snapshot binding.
- Generic remote time_limit_s handling in web/server.py::_parse_diagnose_request.
- TargetAdapterRegistry scheme ownership, replacement, unregister, re-registration,
  and concurrent access.
- URI validation (invalid ports, malformed URIs, duplicate query params),
  secret redaction (including custom describe_fn), discovery exception isolation,
  and backward compatibility.
"""

from __future__ import annotations

import concurrent.futures
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from extractor.adapters import (  # noqa: E402
    DEFAULT_ADAPTER_REGISTRY,
    DefaultTargetIdentityPolicy,
    StrictBuildIdIdentityPolicy,
    TargetAdapterRegistry,
    TargetIdentityPolicy,
    TransportFieldSpec,
    TransportMetadata,
    parse_target_uri,
)
from extractor.agent_runtime import AgentRuntime  # noqa: E402
from extractor.capture_backend import (  # noqa: E402
    DurableTrustStore,
    LiveCaptureReceipt,
    MissingIdentityFieldError,
)
from extractor.expert_diagnostic_engine import TargetSpec  # noqa: E402
from extractor.target_adapter import (  # noqa: E402
    LocalTargetAdapter,
    RemoteSshTargetAdapter,
)
from extractor.web.server import WebApiAdapter  # noqa: E402


class _CustomTaggedIdentityPolicy(DefaultTargetIdentityPolicy):
    policy_id = "custom-corp-identity-policy"
    policy_version = "2.3"

    def resolve_build_id(self, identity, tx_metadata=None):
        bid, err = super().resolve_build_id(identity, tx_metadata)
        if bid and isinstance(tx_metadata, dict):
            tx_metadata["custom_policy_applied"] = True
        return bid, err


class _LivePolicyTestAdapter(LocalTargetAdapter):
    """Adapter running real CaptureTransaction + LiveCaptureReceipt + DurableTrustStore."""

    def __init__(self, *, identity: dict, policy: TargetIdentityPolicy, trust_store: DurableTrustStore):
        super().__init__()
        self._fake_identity = dict(identity)
        self._policy = policy
        self.trust_store = trust_store

    def get_identity_policy(self) -> TargetIdentityPolicy:
        return self._policy

    def check_liveness(self, pid: int):
        return True, None

    def get_process_identity(self, pid: int, force: bool = False):
        return dict(self._fake_identity)

    def _run_physical_capture_and_issue_receipt(self, pid: int, session_id: str):
        tx = self.begin_capture_transaction(pid=pid, session_id=session_id, operation_type="diagnostic")
        # Record a real verified read inside the active transaction
        tx.physical_bytes_read = 64
        tx.physical_reads_count = 1
        tx.read_operations.append({
            "address": 0x1000,
            "requested_size": 64,
            "actual_bytes_read": 64,
            "status": "OBSERVED",
            "data": b"\xab" * 64,
        })
        tx.snapshot_binding = f"snap_bind:{pid}:tx_{tx.transaction_id}"
        self.commit_capture_transaction(tx)
        rcpt = self.issue_live_receipt_for_session(
            pid=pid,
            session_id=session_id,
            snapshot_binding=tx.snapshot_binding,
            transaction=tx,
        )
        return tx, rcpt


class TestP1IdentityPolicyLifecycleIntegration(unittest.TestCase):
    def _new_store(self, tmpdir: str) -> DurableTrustStore:
        return DurableTrustStore(os.path.join(tmpdir, "trust_store.json"))

    def test_custom_policy_propagates_end_to_end_through_capture_receipt_and_trust_store(self):
        with tempfile.TemporaryDirectory() as tmp:
            ts = self._new_store(tmp)
            pol = _CustomTaggedIdentityPolicy()
            ident = {
                "pid": 2001,
                "start_time": 123456,
                "process_identity": "boot-uuid-1:2001:123456",
                "executable_identity": "/opt/bin/svc:101",
                "boot_id": "boot-uuid-1",
                "executable": "/opt/bin/svc",
                "exe_fingerprint": "101:2048:1700000000",
                "build_id": "abcdef0123456789",
            }
            ad = _LivePolicyTestAdapter(identity=ident, policy=pol, trust_store=ts)
            tx, rcpt = ad._run_physical_capture_and_issue_receipt(2001, "sess_custom_1")

            # Provenance recorded on transaction and HMAC-signed into receipt target_constraints
            self.assertEqual(tx.metadata.get("identity_policy_id"), "custom-corp-identity-policy")
            self.assertEqual(tx.metadata.get("identity_policy_version"), "2.3")
            self.assertEqual(tx.metadata.get("identity_verification_mode"), "verified_build_id")
            self.assertTrue(tx.metadata.get("custom_policy_applied"))

            self.assertEqual(rcpt.target_constraints["identity_policy_id"], "custom-corp-identity-policy")
            self.assertEqual(rcpt.target_constraints["identity_policy_version"], "2.3")
            self.assertEqual(rcpt.target_constraints["identity_verification_mode"], "verified_build_id")
            self.assertEqual(rcpt.build_id, "abcdef0123456789")

            # Receipt bound in DurableTrustStore
            ts.load()
            self.assertIn(tx.transaction_id, ts.used_operation_ids)
            self.assertEqual(ts.used_operation_ids[tx.transaction_id].get("receipt_id"), rcpt.receipt_id)

            # Validation with matching custom policy succeeds
            ok, msg = rcpt.verify(
                expected_session_id="sess_custom_1",
                expected_pid=2001,
                expected_build_id="abcdef0123456789",
                expected_snapshot_binding=tx.snapshot_binding,
                identity_policy=pol,
            )
            self.assertTrue(ok, msg)

            # Deserialized receipt WITHOUT policy MUST NOT silently fall back to DEFAULT_IDENTITY_POLICY
            roundtrip = LiveCaptureReceipt.from_dict(rcpt.to_dict())
            ok_no_pol, msg_no_pol = roundtrip.verify(
                expected_session_id="sess_custom_1",
                expected_pid=2001,
                expected_build_id="abcdef0123456789",
            )
            self.assertFalse(ok_no_pol)
            self.assertIn("missing_required_identity_policy", msg_no_pol)

            # Policy mismatch between capture and validation MUST fail closed
            ok_mis, msg_mis = roundtrip.verify(
                expected_session_id="sess_custom_1",
                expected_pid=2001,
                expected_build_id="abcdef0123456789",
                identity_policy=DefaultTargetIdentityPolicy(),
            )
            self.assertFalse(ok_mis)
            self.assertIn("identity_policy_mismatch", msg_mis)

    def test_strict_policy_rejects_missing_build_id_at_capture_transaction(self):
        with tempfile.TemporaryDirectory() as tmp:
            ts = self._new_store(tmp)
            ident = {
                "pid": 2002,
                "start_time": 123456,
                "boot_id": "boot-uuid-1",
                "executable": "/opt/bin/no_bid",
                "exe_fingerprint": "102:4096:1700000001",
                "build_id": None,
            }
            ad = _LivePolicyTestAdapter(identity=ident, policy=StrictBuildIdIdentityPolicy(), trust_store=ts)
            tx = ad.begin_capture_transaction(pid=2002, session_id="sess_strict", operation_type="diagnostic")
            tx.physical_bytes_read = 32
            tx.physical_reads_count = 1
            tx.read_operations.append({"address": 0x1000, "requested_size": 32, "actual_bytes_read": 32, "status": "OBSERVED", "data": b"x" * 32})
            with self.assertRaises(MissingIdentityFieldError):
                ad.commit_capture_transaction(tx)

    def test_default_policy_no_build_id_end_to_end_and_rejects_missing_or_mismatched_actual(self):
        with tempfile.TemporaryDirectory() as tmp:
            ts = self._new_store(tmp)
            pol = DefaultTargetIdentityPolicy()
            ident = {
                "pid": 2003,
                "start_time": 123456,
                "process_identity": "boot-uuid-1:2003:123456",
                "executable_identity": "/opt/bin/no_bid:103",
                "boot_id": "boot-uuid-1",
                "executable": "/opt/bin/no_bid",
                "exe_fingerprint": "103:8192:1700000002",
                "build_id": None,
            }
            ad = _LivePolicyTestAdapter(identity=ident, policy=pol, trust_store=ts)
            tx, rcpt = ad._run_physical_capture_and_issue_receipt(2003, "sess_nobid")

            self.assertTrue(rcpt.build_id.startswith("no-build-id:"))
            self.assertEqual(rcpt.target_constraints["identity_verification_mode"], "synthetic_no_build_id")

            # Validating with matching synthetic identity succeeds
            ok, msg = rcpt.verify(
                expected_session_id="sess_nobid",
                expected_pid=2003,
                expected_build_id=rcpt.build_id,
                expected_snapshot_binding=tx.snapshot_binding,
                identity_policy=pol,
            )
            self.assertTrue(ok, msg)

            # Mismatched executable fingerprint MUST fail
            ok_fp, msg_fp = rcpt.verify(
                expected_session_id="sess_nobid",
                expected_pid=2003,
                expected_build_id="no-build-id:000000000000000000000000",
                identity_policy=pol,
            )
            self.assertFalse(ok_fp)
            self.assertIn("mismatched_executable_fingerprint", msg_fp)

            # Missing actual build_id MUST NOT pass against synthetic expected build_id
            ok_empty, msg_empty = pol.validate_build_id_match(rcpt.build_id, "")
            self.assertFalse(ok_empty)
            self.assertIn("missing_actual_build_id", msg_empty)


class TestP2GenericRemoteTimeLimitsAndValidation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.web = WebApiAdapter(AgentRuntime(corpus_dir=os.path.join(self.tmp.name, "corpus")))
        DEFAULT_ADAPTER_REGISTRY.register(
            "xssh",
            factory=lambda p: LocalTargetAdapter(),
            metadata=TransportMetadata(
                id="xssh",
                label_en="XSSH",
                label_ko="XSSH",
                uri_schemes=("xssh",),
                is_remote=True,
                requires_debug_image=True,
                fields=(
                    TransportFieldSpec(
                        name="target_name",
                        label_en="Target",
                        label_ko="대상",
                        required=True,
                    ),
                ),
            ),
            uri_schemes=("xssh",),
            replace=True,
        )

    def tearDown(self):
        DEFAULT_ADAPTER_REGISTRY.unregister("xssh")
        self.tmp.cleanup()

    def test_local_ssh_and_custom_remote_time_limits(self):
        # Local transport capped at DIAGNOSE_MAX_TIME_LIMIT_S
        loc = self.web._parse_diagnose_request({"pid": 4242, "time_limit_s": 999})
        self.assertTrue(loc["success"], loc)
        self.assertEqual(loc["args"]["time_limit_s"], self.web.DIAGNOSE_MAX_TIME_LIMIT_S)

        # Legacy SSH transport capped at DIAGNOSE_REMOTE_MAX_TIME_LIMIT_S
        ssh = self.web._parse_diagnose_request({"pid": 4242, "remote_host": "10.0.0.5", "time_limit_s": 999})
        self.assertTrue(ssh["success"], ssh)
        self.assertEqual(ssh["args"]["time_limit_s"], self.web.DIAGNOSE_REMOTE_MAX_TIME_LIMIT_S)

        # Custom remote transport (no remote_host!) ALSO capped at DIAGNOSE_REMOTE_MAX_TIME_LIMIT_S
        custom = self.web._parse_diagnose_request({
            "pid": 4242,
            "transport": "xssh",
            "transport_params": {"target_name": "board-01"},
            "time_limit_s": 999,
        })
        self.assertTrue(custom["success"], custom)
        self.assertEqual(custom["args"]["time_limit_s"], self.web.DIAGNOSE_REMOTE_MAX_TIME_LIMIT_S)

        # Custom remote URI ALSO capped at DIAGNOSE_REMOTE_MAX_TIME_LIMIT_S
        custom_uri = self.web._parse_diagnose_request({
            "pid": 4242,
            "target_uri": "xssh://board-01",
            "time_limit_s": 999,
        })
        self.assertTrue(custom_uri["success"], custom_uri)
        self.assertEqual(custom_uri["args"]["time_limit_s"], self.web.DIAGNOSE_REMOTE_MAX_TIME_LIMIT_S)

    def test_unknown_transport_and_malformed_or_missing_params_rejected(self):
        unk = self.web._parse_diagnose_request({"pid": 4242, "transport": "nonexistent"})
        self.assertFalse(unk["success"])
        self.assertEqual(unk["error"]["code"], "INVALID_PARAM")

        missing_req = self.web._parse_diagnose_request({"pid": 4242, "transport": "xssh", "transport_params": {}})
        self.assertFalse(missing_req["success"])
        self.assertIn("target_name", missing_req["error"]["message"])

        bad_tp = self.web._parse_diagnose_request({"pid": 4242, "transport": "xssh", "transport_params": "not_a_dict"})
        self.assertFalse(bad_tp["success"])
        self.assertEqual(bad_tp["error"]["code"], "INVALID_PARAM")


class TestP2RegistryConsistencyAndUriSecrets(unittest.TestCase):
    def test_scheme_ownership_collision_replace_unregister_and_concurrency(self):
        reg = TargetAdapterRegistry()
        reg.register("alpha", factory=lambda p: ("alpha", p), uri_schemes=("shared", "a1"))
        self.assertEqual(reg.scheme_owner("shared"), "alpha")

        # Duplicate scheme by another transport rejected by default
        with self.assertRaises(ValueError):
            reg.register("beta", factory=lambda p: ("beta", p), uri_schemes=("shared",))

        # Explicit allow_scheme_override transfers ownership cleanly
        reg.register("beta", factory=lambda p: ("beta", p), uri_schemes=("shared",), allow_scheme_override=True)
        self.assertEqual(reg.scheme_owner("shared"), "beta")
        self.assertNotIn("shared", reg.get("alpha").uri_schemes)

        # replace=True drops stale scheme mappings
        reg.register("alpha", factory=lambda p: ("alpha2", p), uri_schemes=("a2",), replace=True)
        self.assertIsNone(reg.scheme_owner("a1"))
        self.assertEqual(reg.scheme_owner("a2"), "alpha")

        # unregister cleans up schemes and allows re-registration
        self.assertTrue(reg.unregister("alpha"))
        self.assertIsNone(reg.scheme_owner("a2"))
        reg.register("gamma", factory=lambda p: ("gamma", p), uri_schemes=("a2",))
        self.assertEqual(reg.scheme_owner("a2"), "gamma")

        # Concurrent register / list / dispatch stays consistent
        def _worker(i: int):
            tid = f"t{i}"
            reg.register(tid, factory=lambda p, x=tid: x, uri_schemes=(f"sc{i}",))
            _ = reg.list_transport_metadata(include_destinations=False)
            out = reg.dispatch(f"sc{i}://host{i}")
            reg.unregister(tid)
            return out

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            results = list(ex.map(_worker, range(16)))
        self.assertEqual(len(results), 16)

    def test_uri_validation_secret_redaction_and_discovery_exception_isolation(self):
        # Malformed URIs, invalid ports, duplicate query parameters
        for bad in (
            "not_a_uri",
            "ssh://host:0",
            "ssh://host:70000",
            "ssh://host:abc",
            "ssh://host with space",
            "ssh://host?ssh_user=a&ssh_user=b",
            "123://host",
        ):
            with self.assertRaises(ValueError, msg=bad):
                parse_target_uri(bad)

        # Secret redaction even when custom describe_fn returns secret fields
        reg = TargetAdapterRegistry()
        reg.register(
            "sec",
            factory=lambda p: p,
            metadata=TransportMetadata(
                id="sec",
                label_en="SEC",
                label_ko="SEC",
                uri_schemes=("sec",),
                fields=(
                    TransportFieldSpec(name="board", label_en="Board", label_ko="보드", required=True),
                    TransportFieldSpec(name="custom_secret_pin", label_en="PIN", label_ko="PIN", secret=True),
                ),
                discover_destinations=lambda: (_ for _ in ()).throw(RuntimeError("network down")),
            ),
            describe_fn=lambda p: {
                "transport": "sec",
                "board": p.get("board"),
                "password": "leaked-password",
                "custom_secret_pin": p.get("custom_secret_pin"),
                "nested": {"token": "leaked-token", "safe": "ok"},
            },
        )
        desc = reg.describe({"transport": "sec", "transport_params": {"board": "b1", "custom_secret_pin": "9999"}})
        self.assertEqual(desc["board"], "b1")
        self.assertNotIn("password", desc)
        self.assertNotIn("custom_secret_pin", desc)
        self.assertNotIn("token", desc["nested"])
        self.assertEqual(desc["nested"]["safe"], "ok")

        # Discovery exception is isolated and never crashes metadata API
        metas = reg.list_transport_metadata(include_destinations=True)
        self.assertEqual(metas[0]["destinations"], [])
        self.assertTrue(metas[0].get("discovery_error"))

    def test_backward_compatibility_legacy_target_spec_and_adapters(self):
        spec = TargetSpec.from_value({"host": "10.1.2.3", "user": "ops", "port": 2222, "identity": "/tmp/id_rsa"})
        self.assertEqual(spec.remote_host, "10.1.2.3")
        self.assertEqual(spec.ssh_user, "ops")
        self.assertEqual(spec.ssh_port, 2222)
        ad = spec.build_adapter()
        self.assertIsInstance(ad, RemoteSshTargetAdapter)
        desc = spec.describe()
        self.assertEqual(desc["transport"], "ssh")
        self.assertEqual(desc["host"], "10.1.2.3")
        self.assertNotIn("ssh_key", desc)
        self.assertNotIn("identity", desc)


if __name__ == "__main__":
    unittest.main()
