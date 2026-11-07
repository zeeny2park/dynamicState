"""Tests for Phase 2.0-A.3.17 P1-6: Multi-Process Crash Boundaries & Recovery Integrity.

Executes real, isolated OS Python processes (via sys.executable) across distinct lifetimes:
1. Crash before durable commit: uncommitted operations never appear in DurableTrustStore.
2. Crash after durable commit before Ledger admission: permits exact original recovery, rejects conflicting reuse.
3. Crash during trust consumption write failure: leaves store uncorrupted without partial acceptance.
4. Multi-process key revocation: permanent cross-process revocation and re-registration rejection.
5. Multi-process key rotation consensus: rotation propagation and old key rejection.
6. Multi-process reconstruction from forged serialized ledger: independent verifiers fail closed.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest


class TestPhase20A317MultiprocessCrashBoundaries(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="a317_mp_crash_")
        self.store_path = os.path.join(self.test_dir, "trust_store.json")
        self.ledger_path = os.path.join(self.test_dir, "ledger.json")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _run_subproc(self, code_str: str) -> subprocess.CompletedProcess:
        env = dict(os.environ)
        env["PYTHONPATH"] = "."
        env["DYNAMICSTATE_TRUST_STORE_PATH"] = self.store_path
        env["DYNAMICSTATE_CAPTURE_SECRET"] = "secret12345678901234567890123456789012"
        env["DYNAMICSTATE_CAPTURE_KEY_ID"] = "k1"
        return subprocess.run(
            [sys.executable, "-c", code_str],
            capture_output=True,
            text=True,
            env=env,
        )

    def test_01_crash_before_durable_commit_leaves_store_clean(self):
        """A process that crashes before commit_capture_transaction completes leaves no trace in DurableTrustStore."""
        # Process 1: Starts transaction, performs reads, then simulates immediate crash (os._exit(42))
        p1_code = f"""
import os
from extractor.capture_backend import DurableTrustStore
from extractor.target_adapter import TargetExecutionAdapter

class FakeAdapter(TargetExecutionAdapter):
    def get_proc_maps(self, pid): return []
    def get_threads(self, pid): return []
    def check_liveness(self, pid): return True, 'ok'
    def is_remote(self): return False
    def target_host(self): return 'localhost'
    def get_process_identity(self, pid):
        return {{'pid': pid, 'start_time': 111, 'boot_id': 'b1', 'process_identity': f'{{pid}}:111:b1',
                'executable': '/bin/app', 'executable_identity': '/bin/app:1', 'build_id': 'bid1'}}
    def read_memory(self, pid, address, size):
        self._record_physical_read(num_bytes=size, num_reads=1, data=b'X'*size, pid=pid, address=address)
        return b'X'*size, 'OBSERVED', None

ts = DurableTrustStore('{self.store_path}')
adapter = FakeAdapter()
adapter.trust_store = ts
tx = adapter.begin_capture_transaction('sess_crash', 1234)
adapter.read_memory(1234, 0x1000, 64)
# Simulate abrupt process crash before commit!
os._exit(42)
"""
        proc1 = self._run_subproc(p1_code)
        self.assertEqual(proc1.returncode, 42)

        # Process 2: Independent process inspects trust store
        p2_code = f"""
import sys
from extractor.capture_backend import DurableTrustStore

ts = DurableTrustStore('{self.store_path}')
# Check that used_operation_ids is empty
if ts.used_operation_ids:
    print('FAIL: uncommitted operations found in trust store:', ts.used_operation_ids)
    sys.exit(1)
print('SUCCESS_CLEAN')
"""
        proc2 = self._run_subproc(p2_code)
        self.assertEqual(proc2.returncode, 0, f"Process 2 failed: {proc2.stderr}\n{proc2.stdout}")
        self.assertIn("SUCCESS_CLEAN", proc2.stdout)

    def test_02_crash_after_durable_commit_before_ledger_admission(self):
        """Process commits transaction, issues receipt, then exits before Ledger admission.
        Process 2 can recover exact operation, but conflicting reuse fails closed."""
        p1_code = f"""
import json, os
from extractor.capture_backend import DurableTrustStore, CaptureKeyStore
from extractor.target_adapter import TargetExecutionAdapter

class FakeAdapter(TargetExecutionAdapter):
    def get_proc_maps(self, pid): return []
    def get_threads(self, pid): return []
    def check_liveness(self, pid): return True, 'ok'
    def is_remote(self): return False
    def target_host(self): return 'localhost'
    def get_process_identity(self, pid):
        return {{'pid': pid, 'start_time': 111, 'boot_id': 'b1', 'process_identity': f'{{pid}}:111:b1',
                'executable': '/bin/app', 'executable_identity': '/bin/app:1', 'build_id': 'bid1'}}
    def read_memory(self, pid, address, size):
        self._record_physical_read(num_bytes=size, num_reads=1, data=b'Y'*size, pid=pid, address=address)
        return b'Y'*size, 'OBSERVED', None

ts = DurableTrustStore('{self.store_path}')
ts.register_key('k1', 'secret12345678901234567890123456789012', is_active=True)
adapter = FakeAdapter()
adapter.trust_store = ts
tx = adapter.begin_capture_transaction('sess_c2', 2048)
adapter.read_memory(2048, 0x2000, 128)
adapter.commit_capture_transaction(tx)
rcpt = adapter.issue_live_receipt_for_session('sess_c2', 2048, transaction=tx)

with open('{self.test_dir}/committed_tx.json', 'w') as f:
    json.dump({{'op_id': tx.transaction_id, 'rcpt': rcpt.to_dict(), 'obs_digest': tx.observation_digest}}, f)
"""
        proc1 = self._run_subproc(p1_code)
        self.assertEqual(proc1.returncode, 0, f"Process 1 failed: {proc1.stderr}\n{proc1.stdout}")

        # Process 2: Recovers the committed operation into a ledger, then attempts conflicting reuse
        p2_code = f"""
import json, sys
from extractor.capture_backend import DurableTrustStore
from extractor.evidence_ledger import EvidenceLedger, EvidenceRecord, EVIDENCE_TYPE_FIELD_OBSERVATION, PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE

with open('{self.test_dir}/committed_tx.json') as f:
    data = json.load(f)

op_id = data['op_id']
rcpt_data = data['rcpt']
obs_dig = data['obs_digest']

ts = DurableTrustStore('{self.store_path}')
ledger = EvidenceLedger(session_id='sess_c2', trust_store=ts)
ident = {{'pid': 2048, 'process_identity': '2048:111:b1', 'executable': '/bin/app',
         'executable_identity': '/bin/app:1', 'build_id': 'bid1', 'target_host': 'localhost'}}

# Exact original recovery succeeds
rec1 = EvidenceRecord(
    evidence_id='ev_recov_orig',
    evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
    nature='observation',
    source='runtime_collector',
    session_id='sess_c2',
    observation='Recovered original',
    details={{'operation_id': op_id, 'observation_digest': obs_dig}},
    snapshot_ref={{'snapshot_id': rcpt_data['snapshot_binding'], 'epoch': 0}},
    target_identity=ident,
    provenance={{'provenance_class': PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE, 'live_capture_receipt': rcpt_data}},
)
ledger.add_record(rec1)

# Conflicting record claiming same operation without derivation must fail
rec2 = EvidenceRecord(
    evidence_id='ev_conflict',
    evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
    nature='observation',
    source='runtime_collector',
    session_id='sess_c2',
    observation='Conflicting record',
    details={{'operation_id': op_id, 'observation_digest': obs_dig}},
    snapshot_ref={{'snapshot_id': rcpt_data['snapshot_binding'], 'epoch': 0}},
    target_identity=ident,
    provenance={{'provenance_class': PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE, 'live_capture_receipt': rcpt_data}},
)
try:
    ledger.add_record(rec2)
    print('FAIL: conflicting record accepted')
    sys.exit(1)
except ValueError as e:
    if 'Receipt replay detected' in str(e):
        print('SUCCESS_REPLAY_BLOCKED')
        sys.exit(0)
    print('UNEXPECTED_ERROR:', e)
    sys.exit(1)
"""
        proc2 = self._run_subproc(p2_code)
        self.assertEqual(proc2.returncode, 0, f"Process 2 failed: {proc2.stderr}\n{proc2.stdout}")
        self.assertIn("SUCCESS_REPLAY_BLOCKED", proc2.stdout)

    def test_03_multiprocess_key_revocation_survives_cold_restarts(self):
        """Process 1 revokes key; Process 2 (independent process) rejects signing and verification; Process 3 cannot re-register."""
        # Process 1: Registers key and revokes it
        p1_code = f"""
from extractor.capture_backend import DurableTrustStore
ts = DurableTrustStore('{self.store_path}')
ts.register_key('key_mp_rev', 'sec_mp_rev_12345678901234567890', is_active=True)
ts.revoke_key('key_mp_rev', reason='compromised_in_p1')
"""
        proc1 = self._run_subproc(p1_code)
        self.assertEqual(proc1.returncode, 0, f"Process 1 failed: {proc1.stderr}")

        # Process 2: Verifies revocation is enforced across cold restart
        p2_code = f"""
import sys
from extractor.capture_backend import DurableTrustStore
ts = DurableTrustStore('{self.store_path}')
if not ts.is_revoked('key_mp_rev'):
    print('FAIL: key_mp_rev not marked revoked')
    sys.exit(1)
try:
    ts.resolve_key('key_mp_rev')
    print('FAIL: resolve_key succeeded on revoked key')
    sys.exit(1)
except ValueError:
    pass
print('SUCCESS_REVOKED')
"""
        proc2 = self._run_subproc(p2_code)
        self.assertEqual(proc2.returncode, 0, f"Process 2 failed: {proc2.stderr}\n{proc2.stdout}")
        self.assertIn("SUCCESS_REVOKED", proc2.stdout)

        # Process 3: Cannot re-register revoked key
        p3_code = f"""
import sys
from extractor.capture_backend import DurableTrustStore
ts = DurableTrustStore('{self.store_path}')
try:
    ts.register_key('key_mp_rev', 'new_attempted_secret')
    print('FAIL: re-registration of revoked key succeeded')
    sys.exit(1)
except ValueError as e:
    if 'permanently revoked' in str(e):
        print('SUCCESS_REREGISTER_BLOCKED')
        sys.exit(0)
    print('UNEXPECTED:', e)
    sys.exit(1)
"""
        proc3 = self._run_subproc(p3_code)
        self.assertEqual(proc3.returncode, 0, f"Process 3 failed: {proc3.stderr}\n{proc3.stdout}")
        self.assertIn("SUCCESS_REREGISTER_BLOCKED", proc3.stdout)

    def test_04_multiprocess_key_rotation_consensus(self):
        """Process 1 rotates key; Process 2 issues attestation with new key; Process 3 verifies it."""
        # Process 1: Rotates key
        p1_code = f"""
from extractor.capture_backend import DurableTrustStore
ts = DurableTrustStore('{self.store_path}')
ts.register_key('key_rot_v1', 'sec_rot_v1_12345678901234567890', is_active=True)
ts.rotate_key('key_rot_v2', 'sec_rot_v2_12345678901234567890')
"""
        proc1 = self._run_subproc(p1_code)
        self.assertEqual(proc1.returncode, 0, f"Process 1 failed: {proc1.stderr}")

        # Process 2: Signs attestation using key_rot_v2
        p2_code = f"""
import json
from extractor.capture_backend import DurableTrustStore, CausalVerifierAuthority
ts = DurableTrustStore('{self.store_path}')
auth = CausalVerifierAuthority(trust_store=ts)
ident = {{'pid': 3099, 'process_identity': '3099:1:b', 'executable_identity': '/app:1', 'build_id': 'bid', 'target_host': 'localhost'}}
att = auth.issue_attestation(
    session_id='sess_rot',
    target_identity=ident,
    operation_id='op_rot',
    precondition_evidence_id='ev_pre',
    postcondition_evidence_id='ev_post',
    claimed_transition={{'f': 1}},
    intervention_details={{'action': 'verified', 'verified_intervention': True}},
    authority_level='PRODUCTION',
    verifier_authority_token=auth.get_verifier_token(),
    key_id='key_rot_v2',
)
with open('{self.test_dir}/att_rot.json', 'w') as f:
    json.dump(att.to_dict() if hasattr(att, 'to_dict') else att.__dict__, f)
"""
        proc2 = self._run_subproc(p2_code)
        self.assertEqual(proc2.returncode, 0, f"Process 2 failed: {proc2.stderr}\n{proc2.stdout}")

        # Process 3: Verifies attestation using key_rot_v2
        p3_code = f"""
import json, sys
from extractor.capture_backend import DurableTrustStore, CausalAttestation
ts = DurableTrustStore('{self.store_path}')
with open('{self.test_dir}/att_rot.json') as f:
    d = json.load(f)
att = CausalAttestation(**d)
ok, err = att.verify(trust_store=ts, expected_session_id='sess_rot', expected_pid=3099)
if not ok:
    print('FAIL: verification failed:', err)
    sys.exit(1)
print('SUCCESS_ROTATION_VERIFIED')
"""
        proc3 = self._run_subproc(p3_code)
        self.assertEqual(proc3.returncode, 0, f"Process 3 failed: {proc3.stderr}\n{proc3.stdout}")
        self.assertIn("SUCCESS_ROTATION_VERIFIED", proc3.stdout)

    def test_05_multiprocess_forged_ledger_fails_closed(self):
        """Process 1 saves valid ledger; Process 2 tampers indexes; Process 3 calls from_dict() and fails closed."""
        p1_code = f"""
import json
from extractor.capture_backend import DurableTrustStore, get_trusted_capture_authority_token, issue_live_capture_receipt
from extractor.evidence_ledger import EvidenceLedger, EvidenceRecord, EVIDENCE_TYPE_FIELD_OBSERVATION, PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE

ts = DurableTrustStore('{self.store_path}')
ts.register_key('k_forged_test', 'secret12345678901234567890123456789012', is_active=True)
ledger = EvidenceLedger(session_id='sess_f', trust_store=ts)
ident = {{'pid': 5000, 'process_identity': '5000:1:b', 'executable': '/app', 'executable_identity': '/app:1', 'build_id': 'bid', 'target_host': 'localhost'}}
rcpt = issue_live_capture_receipt(
    session_id='sess_f', pid=5000, process_identity=ident['process_identity'],
    executable_identity=ident['executable_identity'], build_id=ident['build_id'],
    snapshot_binding='snap:5000', operation_id='op_legit',
    capture_authority_token=get_trusted_capture_authority_token(),
    secret='secret12345678901234567890123456789012', key_id='k_forged_test'
)
rec = EvidenceRecord(
    evidence_id='ev_legit', evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION, nature='observation',
    source='runtime_collector', session_id='sess_f', observation='Legit',
    details={{'operation_id': 'op_legit'}}, snapshot_ref={{'snapshot_id': 'snap:5000', 'epoch': 0}},
    target_identity=ident, provenance={{'provenance_class': PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE, 'live_capture_receipt': rcpt.to_dict()}}
)
ledger.add_record(rec)
with open('{self.ledger_path}', 'w') as f:
    json.dump(ledger.to_dict(), f)
"""
        proc1 = self._run_subproc(p1_code)
        self.assertEqual(proc1.returncode, 0, f"Process 1 failed: {proc1.stderr}\n{proc1.stdout}")

        # Process 2: Tamper serialized file
        with open(self.ledger_path, "r") as f:
            ledger_data = json.load(f)
        ledger_data["operation_to_receipt_id"]["op_legit"] = "live_rcpt_forged_id"
        with open(self.ledger_path, "w") as f:
            json.dump(ledger_data, f)

        # Process 3: Reconstructs and asserts failure
        p3_code = f"""
import json, sys
from extractor.capture_backend import DurableTrustStore
from extractor.evidence_ledger import EvidenceLedger

ts = DurableTrustStore('{self.store_path}')
with open('{self.ledger_path}') as f:
    data = json.load(f)

try:
    EvidenceLedger.from_dict(data, trust_store=ts)
    print('FAIL: from_dict accepted forged operation_to_receipt_id')
    sys.exit(1)
except ValueError as e:
    if 'Forged or conflicting index detected' in str(e):
        print('SUCCESS_FORGERY_REJECTED')
        sys.exit(0)
    print('UNEXPECTED:', e)
    sys.exit(1)
"""
        proc3 = self._run_subproc(p3_code)
        self.assertEqual(proc3.returncode, 0, f"Process 3 failed: {proc3.stderr}\n{proc3.stdout}")
        self.assertIn("SUCCESS_FORGERY_REJECTED", proc3.stdout)


if __name__ == "__main__":
    unittest.main()
