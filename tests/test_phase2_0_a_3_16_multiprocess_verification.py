"""Phase 2.0-A.3.16 Real Multiprocess Independent Process Verification Tests.

Verifies:
1. Process A creates and signs an attestation.
2. Process B independently verifies it.
3. Process A revokes its signing key.
4. Process B must reject the old attestation with KEY_REVOKED.
5. Process C restarts and reconstructs trust state.
6. Previously consumed attestations remain rejected in Process C.
7. Concurrent replay attempts across independent OS processes result in exactly one success.
8. Corrupted or interrupted trust store persistence fails closed in subsequent processes.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest


class TestPhase20A316MultiprocessVerification(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="a316_mproc_")
        self.store_path = os.path.join(self.tmp_dir, "trust_store.json")
        self.att_path = os.path.join(self.tmp_dir, "attestation.json")

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _run_python_code(self, code: str) -> subprocess.CompletedProcess:
        env = dict(os.environ)
        env["PYTHONPATH"] = "."
        return subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            env=env,
        )

    # Scenarios 1 & 2: Process A signs, Process B verifies
    def test_01_and_02_process_a_signs_process_b_verifies(self):
        # Process A creates key and issues attestation
        code_a = f"""
from extractor.capture_backend import DurableTrustStore, CausalVerifierAuthority
import json

store = DurableTrustStore("{self.store_path}")
store.register_key("key_mproc", "secret_mproc_999", is_active=True)
auth = CausalVerifierAuthority(trust_store=store)

target_ident = {{
    "pid": 9501,
    "process_identity": "9501:1234:boot",
    "executable": "/usr/bin/proc_a",
    "executable_identity": "/usr/bin/proc_a:9501",
    "build_id": "sha1:mproc_build",
    "target_host": "cluster-node.internal",
}}

att = auth.issue_attestation(
    session_id="sess_mproc",
    target_identity=target_ident,
    operation_id="ctx_op_mproc",
    precondition_evidence_id="ev_pre_mproc",
    postcondition_evidence_id="ev_post_mproc",
    claimed_transition={{"worker": "ready"}},
    verifier_authority_token=auth.get_verifier_token(),
    key_id="key_mproc",
)

with open("{self.att_path}", "w") as f:
    json.dump(att.to_dict(), f)
"""
        res_a = self._run_python_code(code_a)
        self.assertEqual(res_a.returncode, 0, f"Process A failed: {res_a.stderr}")
        self.assertTrue(os.path.exists(self.att_path))

        # Process B independently loads trust store and verifies attestation
        code_b = f"""
from extractor.capture_backend import DurableTrustStore, CausalAttestation
import json, sys

store = DurableTrustStore("{self.store_path}")
with open("{self.att_path}", "r") as f:
    att_data = json.load(f)

att = CausalAttestation.from_dict(att_data)
ok, reason = att.verify(trust_store=store, expected_target_host="cluster-node.internal")
if not ok:
    print(f"FAILED: {{reason}}", file=sys.stderr)
    sys.exit(1)
print("VERIFIED")
sys.exit(0)
"""
        res_b = self._run_python_code(code_b)
        self.assertEqual(res_b.returncode, 0, f"Process B failed: {res_b.stderr}")
        self.assertIn("VERIFIED", res_b.stdout)

    # Scenarios 3 & 4: Process A revokes key, Process B rejects attestation
    def test_03_and_04_process_a_revokes_process_b_rejects(self):
        # Run setup first
        self.test_01_and_02_process_a_signs_process_b_verifies()

        # Process A revokes the signing key
        code_revoke = f"""
from extractor.capture_backend import DurableTrustStore
store = DurableTrustStore("{self.store_path}")
store.revoke_key("key_mproc", reason="Attacker breached node")
"""
        res_rev = self._run_python_code(code_revoke)
        self.assertEqual(res_rev.returncode, 0, f"Process A revoke failed: {res_rev.stderr}")

        # Process B must now reject the attestation with KEY_REVOKED
        code_b = f"""
from extractor.capture_backend import DurableTrustStore, CausalAttestation
import json, sys

store = DurableTrustStore("{self.store_path}")
with open("{self.att_path}", "r") as f:
    att_data = json.load(f)

att = CausalAttestation.from_dict(att_data)
ok, reason = att.verify(trust_store=store)
if not ok and "KEY_REVOKED" in reason:
    print(f"REJECTED_AS_EXPECTED: {{reason}}")
    sys.exit(0)
else:
    print(f"UNEXPECTED_RESULT: ok={{ok}}, reason={{reason}}", file=sys.stderr)
    sys.exit(1)
"""
        res_b = self._run_python_code(code_b)
        self.assertEqual(res_b.returncode, 0, f"Process B failed to reject revoked key: {res_b.stderr}")
        self.assertIn("KEY_REVOKED", res_b.stdout)

    # Scenarios 5 & 6: Process C restarts and previously consumed attestations remain rejected
    def test_05_and_06_process_c_restart_anti_replay(self):
        # Process A marks att_single_use as used
        code_consume = f"""
from extractor.capture_backend import DurableTrustStore
store = DurableTrustStore("{self.store_path}")
store.register_key("k_race", "sec_race")
store.record_used_attestation("att_consumed_by_proc_a")
"""
        res_a = self._run_python_code(code_consume)
        self.assertEqual(res_a.returncode, 0, f"Process A consume failed: {res_a.stderr}")

        # Process C starts fresh in independent process and attempts replay
        code_c = f"""
from extractor.capture_backend import DurableTrustStore
import sys

store = DurableTrustStore("{self.store_path}")
if not store.is_attestation_used("att_consumed_by_proc_a"):
    print("Error: store did not remember used attestation", file=sys.stderr)
    sys.exit(1)

try:
    store.record_used_attestation("att_consumed_by_proc_a")
    print("Error: Replay was accepted!", file=sys.stderr)
    sys.exit(2)
except ValueError as e:
    if "replay of causal attestation id" in str(e).lower():
        print("REPLAY_REJECTED")
        sys.exit(0)
    sys.exit(3)
"""
        res_c = self._run_python_code(code_c)
        self.assertEqual(res_c.returncode, 0, f"Process C restart test failed: {res_c.stderr}")
        self.assertIn("REPLAY_REJECTED", res_c.stdout)

    # Scenario 7: Concurrent replay attempts across independent OS processes
    def test_07_concurrent_multiprocess_replay_exactly_one_success(self):
        # Initialize store
        store_init = f"""
from extractor.capture_backend import DurableTrustStore
store = DurableTrustStore("{self.store_path}")
store.register_key("k_race", "sec_race")
"""
        self.assertEqual(self._run_python_code(store_init).returncode, 0)

        # Launch 8 concurrent OS processes attempting to record the same attestation ID
        code_worker = f"""
from extractor.capture_backend import DurableTrustStore
import sys

store = DurableTrustStore("{self.store_path}")
try:
    store.record_used_attestation("race_single_use_att")
    sys.exit(0)  # Success
except ValueError:
    sys.exit(1)  # Rejected as replay
"""
        env = dict(os.environ)
        env["PYTHONPATH"] = "."
        procs = [
            subprocess.Popen([sys.executable, "-c", code_worker], env=env)
            for _ in range(8)
        ]

        exit_codes = [p.wait(timeout=10) for p in procs]
        successes = sum(1 for c in exit_codes if c == 0)
        rejections = sum(1 for c in exit_codes if c == 1)

        self.assertEqual(successes, 1, f"Expected exactly 1 success, got {successes}. Codes: {exit_codes}")
        self.assertEqual(rejections, 7, f"Expected 7 rejections, got {rejections}. Codes: {exit_codes}")

    # Scenario 8: Process termination / corrupt store fails closed
    def test_08_corrupted_store_persistence_fails_closed(self):
        # Process writes corrupt trust store
        with open(self.store_path, "w", encoding="utf-8") as f:
            f.write("{\"schema_version\": \"1.0.0\", \"keys\": { broken json ...")

        # Process B loading must fail closed
        code_fail = f"""
from extractor.capture_backend import DurableTrustStore
import sys

try:
    store = DurableTrustStore("{self.store_path}")
    sys.exit(1)
except RuntimeError as e:
    if "corrupted or unreadable" in str(e).lower():
        sys.exit(0)
    sys.exit(2)
"""
        res_fail = self._run_python_code(code_fail)
        self.assertEqual(res_fail.returncode, 0, f"Expected fail-closed RuntimeError, got: {res_fail.stderr}")


if __name__ == "__main__":
    unittest.main()
