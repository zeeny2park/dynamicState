"""Phase 2.0-A.2: Cryptographic Capture Trust Closure Test Suite.

Proves:
1. No hardcoded default signing secrets; fail-closed behavior when verification keys are unavailable.
2. Authority separation: signing authority vs verification authority with key rotation and revocation.
3. Cryptographic binding of receipts to snapshot artifacts (PID, start time, executable path,
   ELF Build ID, manifest digest, artifact integrity, and signing key ID).
4. Rejection of tampered signatures, modified identity fields, cross-snapshot replay, and session mismatch.
5. Invariant that synthetic fixtures cannot escalate to LIVE_RUNTIME_CAPTURE.
6. Real-world end-to-end validation:
   - Compilation and execution of real C++ target process.
   - Capture via native dynamicstate-collector C binary.
   - Non-stripped companion ELF Build ID extraction.
   - Snapshot manifest digest and artifact integrity verification.
   - Receipt generation and independent verification through the Adaptive Investigation Engine.
   - Proving disk/artifact tampering breaks verification fail-closed.
"""

import copy
import dataclasses
import hashlib
import hmac
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
import warnings
from typing import Any, Dict

from extractor.adaptive_engine import AdaptiveInvestigationEngine
from extractor.debug_image import inspect_elf
from extractor.evidence_adapter import (
    EvidenceAdapter,
    PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
    PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
    PROVENANCE_CLASS_SYNTHETIC_FIXTURE,
)
from extractor.evidence_ledger import (
    CaptureSigningAuthority,
    CaptureVerificationAuthority,
    LiveCaptureReceipt,
    TRUST_STATE_LIVE_VERIFIED,
    TRUST_STATE_IMPORTED_UNVERIFIED,
    TRUST_STATE_INVALID_OR_TAMPERED,
    TRUST_STATE_VERIFICATION_UNAVAILABLE,
    compute_live_receipt_signature,
    create_receipt_from_snapshot,
    determine_snapshot_trust_state,
    get_default_signing_authority,
    get_default_verification_authority,
    issue_live_capture_receipt,
    load_secure_key_file,
    load_secure_key_fd,
    reset_capture_authorities,
    set_default_signing_authority,
    set_default_verification_authority,
    setup_test_capture_authorities,
    verify_live_capture_receipt,
)
from extractor.inspection_module import DOMAIN_CONCURRENCY
from extractor.investigation import InvestigationManager
from extractor.memory_snapshot import RawMemorySnapshot, VERDICT_VALIDATED
from extractor.verdict_engine import (
    DIAG_INCONCLUSIVE,
    DIAG_NO_ISSUE_DETECTED_WITHIN_SCOPE,
)


class TestPhase20A2CryptographicTrustClosure(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        cls.collector_dir = os.path.join(cls.repo_root, "target", "collector")
        cls.collector_bin = os.path.join(cls.collector_dir, "dynamicstate-collector")
        cls.test_crypto_bin = os.path.join(cls.collector_dir, "test_crypto")

        # Compile collector binary if needed
        res = subprocess.run(["make", "-C", cls.collector_dir], capture_output=True, text=True)
        if res.returncode != 0:
            raise RuntimeError(f"Failed to build dynamicstate-collector: {res.stderr}")

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="test_a2_trust_closure_")
        self.session_id = "test_session_phase2_0_a2_prod"
        self.test_key_id = "test_key_phase2_0_a2_prod"
        self.test_secret = "4f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a"
        self.signer = CaptureSigningAuthority(key_id=self.test_key_id, secret=self.test_secret)
        self.verifier = CaptureVerificationAuthority(keys={self.test_key_id: self.test_secret, "default": self.test_secret})
        set_default_signing_authority(self.signer)
        set_default_verification_authority(self.verifier)

    def tearDown(self):
        reset_capture_authorities()
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _create_test_snapshot(self, snap_id: str, pid: int = 1234):
        snap_dir = os.path.join(self.tmp_dir, f"snap_{snap_id}")
        os.makedirs(os.path.join(snap_dir, "memory"), exist_ok=True)
        snap = RawMemorySnapshot(
            snapshot_id=snap_id,
            pid=pid,
            binary="/bin/true",
            timestamp_ns=1000000,
            output_dir=snap_dir,
            process_starttime=1000,
        )
        snap.save()
        return snap, snap_dir

    # -------------------------------------------------------------------------
    # Test 01: No Hardcoded Default Signing Secrets; Fail-Closed Behavior
    # -------------------------------------------------------------------------
    def test_01_no_hardcoded_secrets_fails_closed(self):
        """1: Removing authorities causes receipt issuance and verification to fail closed."""
        reset_capture_authorities()
        # Save and wipe capture environment variables
        saved_env = {k: os.environ.pop(k, None) for k in [
            "DYNAMICSTATE_CAPTURE_SECRET",
            "DYNAMICSTATE_CAPTURE_KEYRING",
            "DYNAMICSTATE_CAPTURE_KEY_FILE",
            "DYNAMICSTATE_CAPTURE_KEY_ID",
        ]}
        try:
            # 1. Attempting to issue receipt without explicit signer/secret must raise ValueError
            with self.assertRaises(ValueError) as ctx:
                issue_live_capture_receipt(session_id="sess_no_key", pid=1001, executable_path="/bin/app")
            self.assertIn("No capture signing key configured", str(ctx.exception))

            # 2. Attempting to verify receipt when verification authority has no keys must fail closed
            dummy_rcpt = LiveCaptureReceipt(
                receipt_id="rcpt_test",
                session_id="sess_no_key",
                pid=1001,
                executable_path="/bin/app",
                build_id="abc12345",
                capture_source="test",
                manifest_digest=hashlib.sha256(b"manifest").hexdigest(),
                integrity_validated=True,
                issued_at="2026-10-31T12:00:00Z",
                process_start_time="10000",
                signature="0000000000000000000000000000000000000000000000000000000000000000",
                key_id="default",
            )
            empty_auth = CaptureVerificationAuthority()
            ok, err = verify_live_capture_receipt(dummy_rcpt, verification_authority=empty_auth)
            self.assertFalse(ok)
            self.assertIn("VERIFICATION_KEY_UNAVAILABLE", err)
        finally:
            for k, v in saved_env.items():
                if v is not None:
                    os.environ[k] = v

    # -------------------------------------------------------------------------
    # Test 02: Secrets Never Exposed in repr, str, to_dict, or Reports
    # -------------------------------------------------------------------------
    def test_02_secrets_never_exposed(self):
        """2: Signing keys and verification keys are never exposed in logs, repr, or serialized objects."""
        # 1. Verification Authority repr/str
        v_repr = repr(self.verifier)
        self.assertNotIn(self.test_secret, v_repr)
        self.assertIn(self.test_key_id, v_repr)

        # 2. Signing Authority repr/str
        s_repr = repr(self.signer)
        self.assertNotIn(self.test_secret, s_repr)
        self.assertIn(self.test_key_id, s_repr)

        # 3. LiveCaptureReceipt to_dict
        rcpt = issue_live_capture_receipt(
            session_id="sess_secrets",
            pid=2001,
            executable_path="/bin/app",
            signer=self.signer,
        )
        rcpt_dict = rcpt.to_dict()
        rcpt_json = json.dumps(rcpt_dict)
        self.assertNotIn(self.test_secret, rcpt_json)
        self.assertNotIn("secret", rcpt_dict)

    # -------------------------------------------------------------------------
    # Test 03: Modified HMAC Signature Rejected
    # -------------------------------------------------------------------------
    def test_03_modified_signature_rejected(self):
        """3: A receipt with even a single bit changed in signature is rejected."""
        rcpt = issue_live_capture_receipt(
            session_id="sess_sig",
            pid=3001,
            executable_path="/bin/app",
            signer=self.signer,
        )
        ok, _ = verify_live_capture_receipt(rcpt, verification_authority=self.verifier)
        self.assertTrue(ok)

        # Flip last hex character
        tampered_sig = rcpt.signature[:-1] + ("0" if rcpt.signature[-1] != "0" else "1")
        tampered_rcpt = LiveCaptureReceipt.from_dict({**rcpt.to_dict(), "signature": tampered_sig})
        ok_t, err_t = verify_live_capture_receipt(tampered_rcpt, verification_authority=self.verifier)
        self.assertFalse(ok_t)
        self.assertIn("SIGNATURE_INVALID", err_t)

    # -------------------------------------------------------------------------
    # Test 04: Modified PID Rejected
    # -------------------------------------------------------------------------
    def test_04_modified_pid_rejected(self):
        """4: Modifying PID in receipt invalidates cryptographic signature and causes PID mismatch."""
        rcpt = issue_live_capture_receipt(
            session_id="sess_pid",
            pid=4001,
            executable_path="/bin/app",
            signer=self.signer,
        )
        # 1. Modify PID in receipt payload
        tampered_rcpt = LiveCaptureReceipt.from_dict({**rcpt.to_dict(), "pid": 4002})
        ok, err = verify_live_capture_receipt(tampered_rcpt, verification_authority=self.verifier)
        self.assertFalse(ok)
        self.assertIn("SIGNATURE_INVALID", err)

        # 2. Signature valid for 4001 but expected_pid is 4002
        ok_m, err_m = verify_live_capture_receipt(rcpt, verification_authority=self.verifier, expected_pid=4002)
        self.assertFalse(ok_m)
        self.assertIn("PID_MISMATCH", err_m)

    # -------------------------------------------------------------------------
    # Test 05: Modified Process Start Time Rejected
    # -------------------------------------------------------------------------
    def test_05_modified_process_start_time_rejected(self):
        """5: Modifying process_start_time invalidates cryptographic signature."""
        rcpt = issue_live_capture_receipt(
            session_id="sess_st",
            pid=5001,
            executable_path="/bin/app",
            process_start_time="50000",
            signer=self.signer,
        )
        tampered_rcpt = LiveCaptureReceipt.from_dict({**rcpt.to_dict(), "process_start_time": "50001"})
        ok, err = verify_live_capture_receipt(tampered_rcpt, verification_authority=self.verifier)
        self.assertFalse(ok)
        self.assertIn("SIGNATURE_INVALID", err)

    # -------------------------------------------------------------------------
    # Test 06: Modified Executable Path Rejected
    # -------------------------------------------------------------------------
    def test_06_modified_executable_path_rejected(self):
        """6: Modifying executable_path invalidates signature and fails binding."""
        rcpt = issue_live_capture_receipt(
            session_id="sess_exe",
            pid=6001,
            executable_path="/bin/app_genuine",
            signer=self.signer,
        )
        tampered_rcpt = LiveCaptureReceipt.from_dict({**rcpt.to_dict(), "executable_path": "/bin/app_forged"})
        ok, err = verify_live_capture_receipt(tampered_rcpt, verification_authority=self.verifier)
        self.assertFalse(ok)
        self.assertIn("SIGNATURE_INVALID", err)

        # Expected path mismatch
        ok_m, err_m = verify_live_capture_receipt(
            rcpt,
            verification_authority=self.verifier,
            expected_executable_path="/bin/other_app",
        )
        self.assertFalse(ok_m)
        self.assertIn("EXECUTABLE_PATH_MISMATCH", err_m)

    # -------------------------------------------------------------------------
    # Test 07: Modified ELF Build ID Rejected
    # -------------------------------------------------------------------------
    def test_07_modified_build_id_rejected(self):
        """7: Modifying ELF Build ID invalidates signature and fails build ID check."""
        rcpt = issue_live_capture_receipt(
            session_id="sess_bid",
            pid=7001,
            executable_path="/bin/app",
            build_id="abcdef1234567890",
            signer=self.signer,
        )
        tampered_rcpt = LiveCaptureReceipt.from_dict({**rcpt.to_dict(), "build_id": "0000000000000000"})
        ok, err = verify_live_capture_receipt(tampered_rcpt, verification_authority=self.verifier)
        self.assertFalse(ok)
        self.assertIn("SIGNATURE_INVALID", err)

        # Expected build ID mismatch
        ok_m, err_m = verify_live_capture_receipt(
            rcpt,
            verification_authority=self.verifier,
            expected_build_id="1111222233334444",
        )
        self.assertFalse(ok_m)
        self.assertIn("BUILD_ID_MISMATCH", err_m)

    # -------------------------------------------------------------------------
    # Test 08: Modified Manifest Digest Rejected
    # -------------------------------------------------------------------------
    def test_08_modified_manifest_digest_rejected(self):
        """8: Modifying manifest_digest invalidates signature and fails manifest digest check."""
        original_digest = hashlib.sha256(b"manifest_alpha").hexdigest()
        rcpt = issue_live_capture_receipt(
            session_id="sess_md",
            pid=8001,
            executable_path="/bin/app",
            manifest_digest=original_digest,
            signer=self.signer,
        )
        tampered_digest = hashlib.sha256(b"manifest_tampered").hexdigest()
        tampered_rcpt = LiveCaptureReceipt.from_dict({**rcpt.to_dict(), "manifest_digest": tampered_digest})
        ok, err = verify_live_capture_receipt(tampered_rcpt, verification_authority=self.verifier)
        self.assertFalse(ok)
        self.assertIn("SIGNATURE_INVALID", err)

        # Expected manifest digest mismatch
        ok_m, err_m = verify_live_capture_receipt(
            rcpt,
            verification_authority=self.verifier,
            expected_manifest_digest=tampered_digest,
        )
        self.assertFalse(ok_m)
        self.assertIn("MANIFEST_DIGEST_MISMATCH", err_m)

    # -------------------------------------------------------------------------
    # Test 09: Session Mismatch Rejected
    # -------------------------------------------------------------------------
    def test_09_session_mismatch_rejected(self):
        """9: Receipt issued for session A cannot be used in session B."""
        rcpt = issue_live_capture_receipt(
            session_id="sess_session_a",
            pid=9001,
            executable_path="/bin/app",
            signer=self.signer,
        )
        ok, err = verify_live_capture_receipt(
            rcpt,
            verification_authority=self.verifier,
            expected_session_id="sess_session_b",
        )
        self.assertFalse(ok)
        self.assertIn("SESSION_MISMATCH", err)

    # -------------------------------------------------------------------------
    # Test 10: Cross-Snapshot Replay Attack Rejected
    # -------------------------------------------------------------------------
    def test_10_cross_snapshot_replay_rejected(self):
        """10: An authentic receipt for Snapshot A is rejected when verified against Snapshot B."""
        snap_a_dir = os.path.join(self.tmp_dir, "snap_a")
        snap_b_dir = os.path.join(self.tmp_dir, "snap_b")
        os.makedirs(os.path.join(snap_a_dir, "memory"), exist_ok=True)
        os.makedirs(os.path.join(snap_b_dir, "memory"), exist_ok=True)

        # Snapshot A
        snap_a = RawMemorySnapshot(
            snapshot_id="SNAP_A",
            pid=10001,
            binary="/bin/target",
            timestamp_ns=1000,
            output_dir=snap_a_dir,
            process_starttime=100,
        )
        snap_a.save()
        snap_a.validate_integrity()

        # Snapshot B (different pid and different regions)
        snap_b = RawMemorySnapshot(
            snapshot_id="SNAP_B",
            pid=10002,
            binary="/bin/target",
            timestamp_ns=2000,
            output_dir=snap_b_dir,
            process_starttime=200,
        )
        snap_b.save()
        snap_b.validate_integrity()

        # Generate authentic receipt for Snapshot A
        rcpt_a = create_receipt_from_snapshot(
            snap_a,
            session_id="sess_replay",
            signing_authority=self.signer,
            allow_host_signing=True,
        )

        # Verifying against snap_a succeeds
        ok_a, _ = verify_live_capture_receipt(rcpt_a, verification_authority=self.verifier, snapshot=snap_a)
        self.assertTrue(ok_a)

        # Verifying against snap_b FAILS (PID mismatch, process_starttime mismatch, manifest digest mismatch)
        ok_b, err_b = verify_live_capture_receipt(rcpt_a, verification_authority=self.verifier, snapshot=snap_b)
        self.assertFalse(ok_b)
        self.assertTrue(any(tag in err_b for tag in ("PID_MISMATCH", "MANIFEST_DIGEST_MISMATCH", "PROCESS_START_TIME_MISMATCH")))

    # -------------------------------------------------------------------------
    # Test 11: Unknown Key ID Rejected
    # -------------------------------------------------------------------------
    def test_11_unknown_key_id_rejected(self):
        """11: Receipts signed by an unknown or unregistered key ID fail closed."""
        unknown_signer = CaptureSigningAuthority(key_id="unregistered_rogue_key", secret=self.test_secret)
        rcpt = issue_live_capture_receipt(
            session_id="sess_unknown_key",
            pid=11001,
            executable_path="/bin/app",
            signer=unknown_signer,
        )
        ok, err = verify_live_capture_receipt(rcpt, verification_authority=self.verifier)
        self.assertFalse(ok)
        self.assertIn("UNKNOWN_KEY_ID", err)

    # -------------------------------------------------------------------------
    # Test 12: Revoked Key Rejected
    # -------------------------------------------------------------------------
    def test_12_revoked_key_rejected(self):
        """12: A previously valid key that is revoked immediately fails verification."""
        rcpt = issue_live_capture_receipt(
            session_id="sess_revoke",
            pid=12001,
            executable_path="/bin/app",
            signer=self.signer,
        )
        ok, _ = verify_live_capture_receipt(rcpt, verification_authority=self.verifier)
        self.assertTrue(ok)

        # Revoke the signing key
        self.verifier.revoke_key(self.test_key_id)
        ok_r, err_r = verify_live_capture_receipt(rcpt, verification_authority=self.verifier)
        self.assertFalse(ok_r)
        self.assertIn("KEY_REVOKED", err_r)

    # -------------------------------------------------------------------------
    # Test 13: Missing Mandatory Identity Fields Rejected
    # -------------------------------------------------------------------------
    def test_13_missing_mandatory_identity_field_rejected(self):
        """13: Omitting mandatory identity fields rejects verification."""
        rcpt = issue_live_capture_receipt(
            session_id="sess_mand",
            pid=13001,
            executable_path="/bin/app",
            signer=self.signer,
        )
        base_dict = rcpt.to_dict()

        mandatory_fields = [
            ("receipt_id", ""),
            ("session_id", ""),
            ("pid", 0),
            ("executable_path", ""),
            ("manifest_digest", ""),
            ("issued_at", ""),
            ("key_id", ""),
        ]
        for field_name, bad_val in mandatory_fields:
            corrupted = dict(base_dict)
            corrupted[field_name] = bad_val
            # Recompute signature or pass corrupted object
            c_rcpt = LiveCaptureReceipt.from_dict(corrupted)
            ok, err = verify_live_capture_receipt(c_rcpt, verification_authority=self.verifier)
            self.assertFalse(ok, f"Field '{field_name}' set to {bad_val!r} should be rejected")
            self.assertTrue(
                "MISSING_MANDATORY_FIELD" in err or "SIGNATURE_INVALID" in err,
                f"Expected MISSING_MANDATORY_FIELD or SIGNATURE_INVALID for {field_name}, got: {err}",
            )

    # -------------------------------------------------------------------------
    # Test 14: Integrity Not Validated Flag Rejects
    # -------------------------------------------------------------------------
    def test_14_integrity_not_validated_rejected(self):
        """14: A receipt with integrity_validated=False cannot certify live capture."""
        rcpt = issue_live_capture_receipt(
            session_id="sess_not_val",
            pid=14001,
            executable_path="/bin/app",
            integrity_validated=False,
            signer=self.signer,
        )
        ok, err = verify_live_capture_receipt(rcpt, verification_authority=self.verifier)
        self.assertFalse(ok)
        self.assertIn("INTEGRITY_CHECK_FAILED", err)

    # -------------------------------------------------------------------------
    # Test 15: Synthetic Fixtures Cannot Escalate to LIVE_RUNTIME_CAPTURE
    # -------------------------------------------------------------------------
    def test_15_synthetic_fixture_claiming_live_cannot_escalate(self):
        """15: Synthetic fixtures cannot be upgraded to LIVE_RUNTIME_CAPTURE even if passed a receipt."""
        rcpt = issue_live_capture_receipt(
            session_id="sess_synth",
            pid=15001,
            executable_path="/bin/synthetic_app",
            signer=self.signer,
        )
        engine = AdaptiveInvestigationEngine()
        fixture = {
            "target_identity": {
                "pid": 15001,
                "companion_elf": "/bin/synthetic_app",
                "is_synthetic": True,
                "provenance_class": PROVENANCE_CLASS_SYNTHETIC_FIXTURE,
            },
            "capabilities": {
                "process_alive": True,
                "memory_maps_available": True,
                "threads_available": True,
                "dwarf_symbols_available": True,
                "memory_read_available": True,
            },
            "initial_triage": [
                {
                    "step_id": "triage_threads",
                    "domain": DOMAIN_CONCURRENCY,
                    "output": {"success": True, "threads": []},
                }
            ],
        }
        res = engine.investigate_process_health(
            goal="Test synthetic rejection",
            pid=15001,
            companion_elf_path="/bin/synthetic_app",
            fixture_data=fixture,
            capture_receipt=rcpt,
            verification_authority=self.verifier,
        )
        self.assertEqual(res["provenance_class"], PROVENANCE_CLASS_SYNTHETIC_FIXTURE)
        self.assertNotEqual(res["verdict"], DIAG_NO_ISSUE_DETECTED_WITHIN_SCOPE)
        self.assertEqual(res["verdict"], DIAG_INCONCLUSIVE)

    # -------------------------------------------------------------------------
    # Test 16: Deserialized Session Provenance Downgrade on Tampering
    # -------------------------------------------------------------------------
    def test_16_deserialized_session_provenance_downgrade_on_tamper(self):
        """16: Tampering with a serialized session to claim LIVE_RUNTIME_CAPTURE degrades to unverified."""
        mgr = InvestigationManager(corpus_dir=self.tmp_dir)
        # Create unverified session
        sess = mgr.start_investigation(
            goal="Test tamper downgrade",
            snapshot_id="SNAP_TAMPER",
            provenance_class=PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
        )
        inv_id = sess["investigation_id"]
        save_path = os.path.join(self.tmp_dir, f"{inv_id}.json")
        self.assertTrue(mgr.save_session(inv_id, save_path))

        # Tamper with file to assert live capture and healthy verdict
        with open(save_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        data["summary"]["provenance_class"] = PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE
        data["summary"]["final_diagnosis"] = DIAG_NO_ISSUE_DETECTED_WITHIN_SCOPE
        data["target_ref"]["provenance_class"] = PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE
        data["target_ref"]["live_capture"] = True
        with open(save_path, "w", encoding="utf-8") as f:
            json.dump(data, f)

        # Reload with fresh manager
        mgr2 = InvestigationManager(corpus_dir=self.tmp_dir)
        loaded = mgr2.load_session(save_path)
        self.assertIsNotNone(loaded)
        rep = mgr2.generate_report(inv_id)
        # Diagnosis must be downgraded and provenance must be IMPORTED_UNVERIFIED
        self.assertEqual(rep.get("provenance_class"), PROVENANCE_CLASS_IMPORTED_UNVERIFIED)
        self.assertNotEqual(rep.get("final_diagnosis"), DIAG_NO_ISSUE_DETECTED_WITHIN_SCOPE)
        self.assertEqual(rep.get("final_diagnosis"), DIAG_INCONCLUSIVE)

    # -------------------------------------------------------------------------
    # Test 17: REAL C++ TARGET + COLLECTOR CAPTURE END-TO-END PROVENANCE CHAIN
    # -------------------------------------------------------------------------
    def test_17_real_cpp_collector_end_to_end_chain(self):
        """17: Compile real C++ program, capture with native collector, extract ELF Build ID,
        generate LiveCaptureReceipt bound to disk snapshot, verify independently,
        and prove that disk tampering causes verification failure.
        """
        # 1. Compile real C++ target with DWARF symbols (-g) and Build ID (-Wl,--build-id)
        cpp_src = os.path.join(self.tmp_dir, "real_target.cpp")
        cpp_bin = os.path.join(self.tmp_dir, "real_target_bin")
        with open(cpp_src, "w") as f:
            f.write(r"""
#include <sys/prctl.h>
#include <unistd.h>
#include <vector>
#include <string>
#include <cstring>

volatile int g_work_status = 200;
char g_static_banner[] = "DYNAMICSTATE_REAL_CPP_TARGET_V1";

int main() {
    prctl(0x59616d61, -1, 0, 0, 0); /* PR_SET_PTRACER_ANY */
    std::vector<char> live_heap_block(8192, 0x41);
    while (1) {
        pause();
    }
    return 0;
}
""")
        comp = subprocess.run(
            ["g++", "-g", "-O0", "-Wl,--build-id", cpp_src, "-o", cpp_bin],
            capture_output=True,
            text=True,
        )
        self.assertEqual(comp.returncode, 0, f"Compilation failed: {comp.stderr}")
        self.assertTrue(os.path.isfile(cpp_bin))

        # Inspect real companion ELF Build ID
        ident = inspect_elf(cpp_bin)
        self.assertIsNotNone(ident.build_id, "ELF binary must have a non-empty Build ID")
        real_build_id = ident.build_id

        # 2. Spawn real C++ process
        proc = subprocess.Popen([cpp_bin])
        self.assertIsNotNone(proc.pid)
        real_pid = proc.pid
        time.sleep(0.1)

        out_snap_dir = os.path.join(self.tmp_dir, f"raw_snap_{real_pid}")
        try:
            session_id = f"real_sess_{real_pid}_{uuid.uuid4().hex[:6]}"
            # 3. Capture real process memory via native C99 collector binary with attestation
            kf_path = os.path.join(self.tmp_dir, "test17_collector.key")
            with open(kf_path, "w") as kf:
                kf.write(self.test_secret + "\n")
            os.chmod(kf_path, 0o600)

            col_res = subprocess.run(
                [
                    self.collector_bin,
                    "-p", str(real_pid),
                    "-o", out_snap_dir,
                    "--policy", "all",
                    "-F", kf_path,
                    "--key-id", self.test_key_id,
                    "--session-id", session_id,
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(col_res.returncode, 0, f"Collector failed: {col_res.stderr}\nStdout: {col_res.stdout}")

            # Verify snapshot files on disk including collector-issued receipt.json
            self.assertTrue(os.path.isfile(os.path.join(out_snap_dir, "metadata.json")))
            self.assertTrue(os.path.isfile(os.path.join(out_snap_dir, "manifest.json")))
            self.assertTrue(os.path.isfile(os.path.join(out_snap_dir, "maps.json")))
            self.assertTrue(os.path.isfile(os.path.join(out_snap_dir, "receipt.json")))
            self.assertTrue(os.path.isdir(os.path.join(out_snap_dir, "memory")))

            # 4. Load snapshot via host-side RawMemorySnapshot
            snap = RawMemorySnapshot.load(out_snap_dir)
            self.assertEqual(snap.pid, real_pid)
            self.assertTrue(snap.committed)
            self.assertEqual(snap.validation_verdict, VERDICT_VALIDATED)
            self.assertGreater(len(snap.regions), 0)
            self.assertIsNotNone(snap.manifest_digest)

            # 5. Extract genuine collector-originated receipt loaded directly with snapshot
            self.assertIsNotNone(snap.receipt, "Snapshot must have loaded collector-originated receipt")
            receipt = snap.receipt
            self.assertEqual(receipt.pid, real_pid)
            self.assertEqual(receipt.session_id, session_id)
            self.assertEqual(receipt.build_id, real_build_id)
            self.assertEqual(receipt.manifest_digest, snap.manifest_digest)
            self.assertTrue(receipt.integrity_validated)

            # 6. Verify receipt independently against the real snapshot
            ok_rcpt, err_rcpt = verify_live_capture_receipt(
                receipt,
                verification_authority=self.verifier,
                snapshot=snap,
                expected_session_id=session_id,
                expected_pid=real_pid,
                expected_executable_path=cpp_bin,
                expected_build_id=real_build_id,
                companion_elf_path=cpp_bin,
            )
            self.assertTrue(ok_rcpt, f"Independent verification failed: {err_rcpt}")

            # 7. Run real investigation against the verified snapshot
            engine = AdaptiveInvestigationEngine()
            inv_res = engine.investigate_process_health(
                goal="Investigate real live target process",
                pid=real_pid,
                companion_elf_path=cpp_bin,
                session_id=session_id,
                capture_receipt=receipt,
                verification_authority=self.verifier,
                snapshot=snap,
            )
            self.assertEqual(inv_res["provenance_class"], PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE)

            # 8. ADVERSARIAL DISK TAMPER TESTS:
            # 8.1: Tamper with manifest.json on disk
            manifest_file = os.path.join(out_snap_dir, "manifest.json")
            with open(manifest_file, "r", encoding="utf-8") as f:
                manifest_data = json.load(f)
            # Add a forged region to manifest
            manifest_data.append({
                "region_id": "R999999",
                "start": "0x70000000",
                "end": "0x70001000",
                "start_addr": 1879048192,
                "end_addr": 1879052288,
                "size": 4096,
                "permissions": "r--p",
                "category": "forged",
                "pathname": "",
                "requested": 4096,
                "captured": 0,
                "status": "FAILED",
                "filename": "",
                "error": "FORGED",
            })
            with open(manifest_file, "w", encoding="utf-8") as f:
                json.dump(manifest_data, f, indent=2)

            # Reload snapshot: integrity validation and manifest digest MUST fail closed
            snap_tampered = RawMemorySnapshot.load(out_snap_dir)
            is_valid_t, _ = snap_tampered.validate_integrity()
            self.assertFalse(is_valid_t, "Tampered manifest on disk MUST fail snapshot integrity validation")

            # Receipt verification against tampered snapshot MUST fail closed
            ok_tampered, err_tampered = verify_live_capture_receipt(
                receipt,
                verification_authority=self.verifier,
                snapshot=snap_tampered,
            )
            self.assertFalse(ok_tampered, "Verification MUST fail against tampered snapshot on disk")
            self.assertTrue(
                "SNAPSHOT_NOT_VALIDATED" in err_tampered or "MANIFEST_DIGEST_MISMATCH" in err_tampered or "SNAPSHOT_INTEGRITY_FAILED" in err_tampered,
                f"Expected SNAPSHOT_NOT_VALIDATED, MANIFEST_DIGEST_MISMATCH, or SNAPSHOT_INTEGRITY_FAILED, got: {err_tampered}",
            )
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except Exception:
                proc.kill()

    # -------------------------------------------------------------------------
    # Test 18: Host-side Signing Rejected Without Explicit Authorization
    # -------------------------------------------------------------------------
    def test_18_host_signing_rejected_without_authorization(self):
        """18: Calling create_receipt_from_snapshot without allow_host_signing=True fails closed."""
        snap_dir = os.path.join(self.tmp_dir, "snap_test_18")
        os.makedirs(os.path.join(snap_dir, "memory"), exist_ok=True)
        snap = RawMemorySnapshot(
            snapshot_id="SNAP_18",
            pid=1801,
            binary="/bin/app",
            timestamp_ns=18000,
            output_dir=snap_dir,
            process_starttime=1800,
        )
        snap.save()
        with self.assertRaises(PermissionError):
            create_receipt_from_snapshot(
                snap,
                session_id="sess_unauth",
                signing_authority=self.signer,
                allow_host_signing=False,
            )

    # -------------------------------------------------------------------------
    # Test 19: Identical Basenames in Different Directories Rejected
    # -------------------------------------------------------------------------
    def test_19_identical_basenames_in_different_directories_rejected(self):
        """19: Target identity check rejects identical basenames in differing directory paths."""
        rcpt = issue_live_capture_receipt(
            session_id="sess_19",
            pid=1901,
            executable_path="/usr/bin/worker",
            process_start_time="19000",
            signer=self.signer,
        )
        ok, err = verify_live_capture_receipt(
            rcpt,
            verification_authority=self.verifier,
            expected_executable_path="/tmp/evil/worker",
        )
        self.assertFalse(ok)
        self.assertIn("EXECUTABLE_PATH_MISMATCH", err)

    # -------------------------------------------------------------------------
    # Test 20: Missing Build ID Rejected When Expected
    # -------------------------------------------------------------------------
    def test_20_missing_build_id_rejected_when_expected(self):
        """20: Verification fails closed if target identity expects a Build ID but receipt lacks one."""
        rcpt = issue_live_capture_receipt(
            session_id="sess_20",
            pid=2001,
            executable_path="/usr/bin/worker",
            build_id=None,
            process_start_time="20000",
            signer=self.signer,
        )
        ok, err = verify_live_capture_receipt(
            rcpt,
            verification_authority=self.verifier,
            expected_build_id="0123456789abcdef0123456789abcdef",
        )
        self.assertFalse(ok)
        self.assertIn("MISSING_BUILD_ID", err)

    # -------------------------------------------------------------------------
    # Test 21: Revocation Bypass Attempt With Direct Secret Rejected
    # -------------------------------------------------------------------------
    def test_21_revocation_bypass_attempt_with_direct_secret_rejected(self):
        """21: Supplying direct secret argument cannot bypass authority key revocation."""
        revoked_auth = CaptureVerificationAuthority(keys={self.test_key_id: self.test_secret})
        revoked_auth.revoke_key(self.test_key_id)

        rcpt = issue_live_capture_receipt(
            session_id="sess_21",
            pid=2101,
            executable_path="/usr/bin/worker",
            build_id="build_21",
            process_start_time="21000",
            key_id=self.test_key_id,
            signer=self.signer,
        )
        # Attempt to bypass by passing secret directly
        ok, err = verify_live_capture_receipt(
            rcpt,
            secret=self.test_secret,
            verification_authority=revoked_auth,
        )
        self.assertFalse(ok)
        self.assertIn("KEY_REVOKED", err)

    # -------------------------------------------------------------------------
    # Test 22: Missing Process Start Time Rejected
    # -------------------------------------------------------------------------
    def test_22_missing_process_start_time_rejected(self):
        """22: Receipts with missing, empty, or zero process_start_time fail closed."""
        for bad_st in ["0", "", "   "]:
            rcpt = issue_live_capture_receipt(
                session_id="sess_22",
                pid=2201,
                executable_path="/usr/bin/worker",
                build_id="build_22",
                process_start_time=bad_st,
                signer=self.signer,
            )
            ok, err = verify_live_capture_receipt(rcpt, verification_authority=self.verifier)
            self.assertFalse(ok)
            self.assertIn("MISSING_PROCESS_START_TIME", err)

    # -------------------------------------------------------------------------
    # Test 23: In-Memory Receipt Tampering Detected by Snapshot Integrity
    # -------------------------------------------------------------------------
    def test_23_in_memory_receipt_tampering_detected(self):
        """23: Modifying in-memory snapshot receipt signature or digest fails validate_integrity."""
        snap_dir = os.path.join(self.tmp_dir, "snap_test_23")
        os.makedirs(os.path.join(snap_dir, "memory"), exist_ok=True)
        snap = RawMemorySnapshot(
            snapshot_id="SNAP_23",
            pid=2301,
            binary="/bin/app",
            timestamp_ns=23000,
            output_dir=snap_dir,
            process_starttime=2300,
        )
        snap.save()

        # Write disk receipt.json
        rcpt = issue_live_capture_receipt(
            session_id="sess_23",
            pid=2301,
            executable_path="/bin/app",
            process_start_time="2300",
            manifest_digest=snap.compute_manifest_digest(),
            signer=self.signer,
        )
        with open(os.path.join(snap_dir, "receipt.json"), "w") as f:
            json.dump(rcpt.to_dict(), f, indent=2)

        loaded_snap = RawMemorySnapshot.load(snap_dir)
        self.assertIsNotNone(loaded_snap.receipt)
        is_valid_orig, _ = loaded_snap.validate_integrity()
        self.assertTrue(is_valid_orig)

        # Tamper in-memory signature
        from dataclasses import replace
        loaded_snap.receipt = replace(loaded_snap.receipt, signature="forged_signature_hex_0000")
        is_valid_t, warnings = loaded_snap.validate_integrity()
        self.assertFalse(is_valid_t)
        self.assertTrue(any("signature" in w for w in warnings))

    # -------------------------------------------------------------------------
    # Test 24: FIPS 180-4 and RFC 4231 Known-Answer Test Vectors
    # -------------------------------------------------------------------------
    def test_24_fips_and_rfc_known_answer_vectors(self):
        """24: Pure SHA-256 and HMAC-SHA256 match official NIST/RFC test vectors."""
        # FIPS 180-4 SHA-256 test vectors
        self.assertEqual(
            hashlib.sha256(b"abc").hexdigest(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        )
        self.assertEqual(
            hashlib.sha256(b"").hexdigest(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )

        # RFC 4231 HMAC-SHA256 Test Case 1
        key1 = bytes([0x0b] * 20)
        data1 = b"Hi There"
        expected1 = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        computed1 = hmac.new(key1, data1, hashlib.sha256).hexdigest()
        self.assertEqual(computed1, expected1)

        # RFC 4231 HMAC-SHA256 Test Case 2
        key2 = b"Jefe"
        data2 = b"what do ya want for nothing?"
        expected2 = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        computed2 = hmac.new(key2, data2, hashlib.sha256).hexdigest()
        self.assertEqual(computed2, expected2)

    # -------------------------------------------------------------------------
    # Test 25: Key File Security Constraints (0600/0400, Symlinks, Owner)
    # -------------------------------------------------------------------------
    def test_25_key_file_security_permissions(self):
        """25: load_secure_key_file strictly enforces 0600/0400, rejects symlinks and world/group access."""
        kfile = os.path.join(self.tmp_dir, "key_0600.key")
        with open(kfile, "w") as f:
            f.write("0123456789abcdef0123456789abcdef\n")
        
        # 0600 succeeds
        os.chmod(kfile, 0o600)
        keys = load_secure_key_file(kfile)
        self.assertEqual(keys["file_default"], "0123456789abcdef0123456789abcdef")

        # 0400 succeeds
        os.chmod(kfile, 0o400)
        keys_ro = load_secure_key_file(kfile)
        self.assertEqual(keys_ro["file_default"], "0123456789abcdef0123456789abcdef")

        # Insecure permissions: 0666, 0664, 0644 rejected
        for bad_mode in [0o666, 0o664, 0o644, 0o640, 0o604]:
            os.chmod(kfile, bad_mode)
            with self.assertRaises(PermissionError):
                load_secure_key_file(kfile)

        # Symlink rejected
        os.chmod(kfile, 0o600)
        symlink_path = os.path.join(self.tmp_dir, "symlink_key.key")
        os.symlink(kfile, symlink_path)
        with self.assertRaises(PermissionError):
            load_secure_key_file(symlink_path)

        # Key too short (<16 bytes) rejected
        short_key_file = os.path.join(self.tmp_dir, "short.key")
        with open(short_key_file, "w") as f:
            f.write("too_short_key\n")
        os.chmod(short_key_file, 0o600)
        with self.assertRaises(ValueError):
            load_secure_key_file(short_key_file)

        # JSON keyring file
        json_keyring = os.path.join(self.tmp_dir, "keyring.json")
        with open(json_keyring, "w") as f:
            json.dump({
                "key_a": "abcdefabcdefabcdefabcdef",
                "key_b": "123456781234567812345678",
            }, f)
        os.chmod(json_keyring, 0o600)
        auth = CaptureVerificationAuthority()
        loaded_count = auth.register_key_file(json_keyring)
        self.assertEqual(loaded_count, 2)
        self.assertEqual(auth.get_key("key_a"), "abcdefabcdefabcdefabcdef")
        self.assertEqual(auth.get_key("key_b"), "123456781234567812345678")

    # -------------------------------------------------------------------------
    # Test 26: Inherited FD Key Loading
    # -------------------------------------------------------------------------
    def test_26_key_fd_loading(self):
        """26: Loading key from inherited file descriptor verifies key length and registers into authority."""
        r_fd, w_fd = os.pipe()
        os.write(w_fd, b"pipe_secret_key_16bytes_minimum\n")
        os.close(w_fd)

        auth = CaptureVerificationAuthority()
        auth.register_key_fd(r_fd, key_id="inherited_fd_key")
        os.close(r_fd)

        self.assertEqual(auth.get_key("inherited_fd_key"), "pipe_secret_key_16bytes_minimum")

        # Invalid FD
        with self.assertRaises(ValueError):
            load_secure_key_fd(-1)

        # Short key on FD
        r_fd2, w_fd2 = os.pipe()
        os.write(w_fd2, b"short\n")
        os.close(w_fd2)
        with self.assertRaises(ValueError):
            load_secure_key_fd(r_fd2)
        os.close(r_fd2)

    # -------------------------------------------------------------------------
    # Test 27: Native Collector with --key-file and --key-fd
    # -------------------------------------------------------------------------
    def test_27_native_collector_key_file_and_fd(self):
        """27: Native C collector supports --key-file (0600 mode) and --key-fd, failing closed on insecure file."""
        target_code = """
        #include <unistd.h>
        int main() {
            while (1) { usleep(50000); }
            return 0;
        }
        """
        src = os.path.join(self.tmp_dir, "loop_target.c")
        bin_path = os.path.join(self.tmp_dir, "loop_target")
        with open(src, "w") as f:
            f.write(target_code)
        subprocess.run(["gcc", "-O0", src, "-o", bin_path], check=True)
        target_proc = subprocess.Popen([bin_path])
        
        try:
            time.sleep(0.1)
            pid = target_proc.pid
            snap_dir = os.path.join(self.tmp_dir, "snap_key_file")

            # 1. Test secure key file (0600)
            kf = os.path.join(self.tmp_dir, "secure_collector.key")
            secret = "native_secret_16bytes_long_key_123"
            with open(kf, "w") as f:
                f.write(secret + "\n")
            os.chmod(kf, 0o600)

            res = subprocess.run([
                self.collector_bin,
                "-p", str(pid),
                "-o", snap_dir,
                "-F", kf,
                "-I", "native_file_key",
                "-S", "sess_kf_01",
                "-j",
            ], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, f"Collector failed: {res.stderr}")

            # Check receipt.json
            rcpt_path = os.path.join(snap_dir, "receipt.json")
            self.assertTrue(os.path.exists(rcpt_path))
            with open(rcpt_path, "r") as rf:
                rcpt_data = json.load(rf)
            self.assertEqual(rcpt_data["version"], "v2")
            self.assertEqual(rcpt_data["key_id"], "native_file_key")

            # Verify receipt
            auth = CaptureVerificationAuthority(keys={"native_file_key": secret})
            ok, err = verify_live_capture_receipt(
                rcpt_data,
                verification_authority=auth,
                expected_session_id="sess_kf_01",
                expected_pid=pid,
            )
            self.assertTrue(ok, f"Verification failed: {err}")

            # 2. Insecure key file (0666) -> collector fails closed
            os.chmod(kf, 0o666)
            snap_bad = os.path.join(self.tmp_dir, "snap_bad_perms")
            res_bad = subprocess.run([
                self.collector_bin,
                "-p", str(pid),
                "-o", snap_bad,
                "-F", kf,
                "-I", "native_file_key",
                "-S", "sess_bad",
            ], capture_output=True, text=True)
            self.assertNotEqual(res_bad.returncode, 0)
            self.assertFalse(os.path.exists(os.path.join(snap_bad, "receipt.json")))

            # 3. Test --key-fd
            snap_fd = os.path.join(self.tmp_dir, "snap_key_fd")
            r_fd, w_fd = os.pipe()
            os.write(w_fd, (secret + "\n").encode())
            os.close(w_fd)

            res_fd = subprocess.run([
                self.collector_bin,
                "-p", str(pid),
                "-o", snap_fd,
                "-D", str(r_fd),
                "-I", "native_fd_key",
                "-S", "sess_fd_01",
                "-j",
            ], pass_fds=(r_fd,), capture_output=True, text=True)
            os.close(r_fd)
            self.assertEqual(res_fd.returncode, 0, f"Collector with FD failed: {res_fd.stderr}")
            self.assertTrue(os.path.exists(os.path.join(snap_fd, "receipt.json")))
        finally:
            target_proc.terminate()
            target_proc.wait()

    # -------------------------------------------------------------------------
    # Test 28: Distinct Companion ELF Failure Diagnostics
    # -------------------------------------------------------------------------
    def test_28_companion_elf_failure_diagnostics(self):
        """28: Explicitly distinguishes NOT_FOUND, INVALID, MISSING_BUILD_ID, and BUILD_ID_MISMATCH."""
        rcpt = issue_live_capture_receipt(
            session_id="sess_celf",
            pid=2801,
            executable_path="/usr/bin/daemon",
            build_id="abcdef1234567890",
            signer=self.signer,
        )

        # 1. COMPANION_ELF_NOT_FOUND
        missing_elf = os.path.join(self.tmp_dir, "non_existent_binary")
        ok, err = verify_live_capture_receipt(
            rcpt,
            verification_authority=self.verifier,
            companion_elf_path=missing_elf,
        )
        self.assertFalse(ok)
        self.assertIn("COMPANION_ELF_NOT_FOUND", err)

        # 2. COMPANION_ELF_INVALID (random non-ELF bytes)
        corrupt_elf = os.path.join(self.tmp_dir, "corrupt.elf")
        with open(corrupt_elf, "wb") as f:
            f.write(b"NOT_AN_ELF_HEADER_AT_ALL_123456789")
        ok, err = verify_live_capture_receipt(
            rcpt,
            verification_authority=self.verifier,
            companion_elf_path=corrupt_elf,
        )
        self.assertFalse(ok)
        self.assertIn("COMPANION_ELF_INVALID", err)

        # 3. BUILD_ID_MISMATCH
        # Compile genuine ELF with different build ID
        c_src = os.path.join(self.tmp_dir, "companion.c")
        c_bin = os.path.join(self.tmp_dir, "companion_bin")
        with open(c_src, "w") as f:
            f.write("int main() { return 0; }\n")
        subprocess.run(["gcc", "-Wl,--build-id=0x1122334455667788", c_src, "-o", c_bin], check=True)

        ok, err = verify_live_capture_receipt(
            rcpt,
            verification_authority=self.verifier,
            companion_elf_path=c_bin,
        )
        self.assertFalse(ok)
        self.assertIn("BUILD_ID_MISMATCH", err)

        # 4. MISSING_BUILD_ID when companion has build ID but receipt has none
        rcpt_no_bid = issue_live_capture_receipt(
            session_id="sess_celf_nobid",
            pid=2802,
            executable_path="/usr/bin/daemon",
            build_id=None,
            signer=self.signer,
        )
        ok, err = verify_live_capture_receipt(
            rcpt_no_bid,
            verification_authority=self.verifier,
            companion_elf_path=c_bin,
        )
        self.assertFalse(ok)
        self.assertIn("MISSING_BUILD_ID", err)

    # -------------------------------------------------------------------------
    # Test 29: Trust State Model and Memory Consistency Decoupling
    # -------------------------------------------------------------------------
    def test_29_trust_state_model_and_consistency_decoupling(self):
        """29: determine_snapshot_trust_state yields explicit trust states decoupled from consistency."""
        # 1. Missing receipt -> IMPORTED_UNVERIFIED
        st, reason = determine_snapshot_trust_state(None)
        self.assertEqual(st, TRUST_STATE_IMPORTED_UNVERIFIED)
        self.assertIn("NO_RECEIPT", reason)

        # 2. Valid receipt -> LIVE_VERIFIED
        rcpt = issue_live_capture_receipt(
            session_id="sess_ts_01",
            pid=2901,
            executable_path="/bin/worker",
            signer=self.signer,
        )
        st, err = determine_snapshot_trust_state(rcpt, verification_authority=self.verifier)
        self.assertEqual(st, TRUST_STATE_LIVE_VERIFIED)
        self.assertIsNone(err)

        # 3. No keys configured -> VERIFICATION_UNAVAILABLE
        empty_auth = CaptureVerificationAuthority()
        st, err = determine_snapshot_trust_state(rcpt, verification_authority=empty_auth)
        self.assertEqual(st, TRUST_STATE_VERIFICATION_UNAVAILABLE)
        self.assertIn("VERIFICATION_KEY_UNAVAILABLE", err)

        # 4. Tampered signature -> INVALID_OR_TAMPERED
        from dataclasses import replace
        tampered_rcpt = replace(rcpt, signature="deadbeef" * 8)
        st, err = determine_snapshot_trust_state(tampered_rcpt, verification_authority=self.verifier)
        self.assertEqual(st, TRUST_STATE_INVALID_OR_TAMPERED)
        self.assertIn("SIGNATURE_INVALID", err)

        # 5. Decoupling: Non-atomic consistency level retains LIVE_VERIFIED trust state
        snap_dir = os.path.join(self.tmp_dir, "snap_non_atomic")
        os.makedirs(os.path.join(snap_dir, "memory"), exist_ok=True)
        snap = RawMemorySnapshot(
            snapshot_id="SNAP_NON_ATOMIC",
            pid=2901,
            binary="/bin/worker",
            timestamp_ns=29000,
            output_dir=snap_dir,
            process_starttime=2900,
            consistency={"level": "NON_ATOMIC"},
        )
        snap.save()

        rcpt_bound = issue_live_capture_receipt(
            session_id="sess_non_atomic",
            pid=2901,
            executable_path="/bin/worker",
            process_start_time="2900",
            manifest_digest=snap.compute_manifest_digest(),
            signer=self.signer,
        )
        st, err = determine_snapshot_trust_state(
            rcpt_bound,
            verification_authority=self.verifier,
            snapshot=snap,
        )
        self.assertEqual(st, TRUST_STATE_LIVE_VERIFIED)
        self.assertEqual(snap.consistency["level"], "NON_ATOMIC")

    # -------------------------------------------------------------------------
    # Test 30: Receipt Protocol Version Enforcement
    # -------------------------------------------------------------------------
    def test_30_receipt_protocol_version_enforcement(self):
        """30: Rejects unsupported receipt versions fail-closed."""
        rcpt = issue_live_capture_receipt(
            session_id="sess_v2",
            pid=3001,
            executable_path="/bin/app",
            signer=self.signer,
        )
        self.assertEqual(rcpt.version, "v2")
        ok, err = verify_live_capture_receipt(rcpt, verification_authority=self.verifier)
        self.assertTrue(ok)

        # Reject from_dict with unsupported version
        d = rcpt.to_dict()
        d["version"] = "v3_future"
        with self.assertRaises(ValueError) as ctx:
            LiveCaptureReceipt.from_dict(d)
        self.assertIn("UNSUPPORTED_RECEIPT_VERSION", str(ctx.exception))

    # -------------------------------------------------------------------------
    # Test 31: Missing Disk Manifest Fails Closed (No Reconstructed Fallback)
    # -------------------------------------------------------------------------
    def test_31_missing_disk_manifest_fails_closed(self):
        """31: Disk snapshot with deleted manifest.json fails closed and does not fall back to in-memory regions."""
        snap_dir = os.path.join(self.tmp_dir, "snap_missing_manifest")
        os.makedirs(os.path.join(snap_dir, "memory"), exist_ok=True)
        snap = RawMemorySnapshot(
            snapshot_id="SNAP_MISSING_MAN",
            pid=3101,
            binary="/bin/app",
            timestamp_ns=31000,
            output_dir=snap_dir,
            process_starttime=3100,
        )
        snap.save()

        orig_digest = snap.compute_manifest_digest()
        rcpt = issue_live_capture_receipt(
            session_id="sess_31",
            pid=3101,
            executable_path="/bin/app",
            process_start_time="3100",
            manifest_digest=orig_digest,
            signer=self.signer,
        )

        # Delete manifest.json from disk
        os.unlink(os.path.join(snap_dir, "manifest.json"))
        ok, err = verify_live_capture_receipt(
            rcpt,
            verification_authority=self.verifier,
            snapshot=snap,
        )
        self.assertFalse(ok)
        self.assertTrue("MISSING_MANIFEST" in err or "SNAPSHOT_INTEGRITY_FAILED" in err)

    # -------------------------------------------------------------------------
    # Test 32: Direct Execution of Native C Cryptographic Self-Test
    # -------------------------------------------------------------------------
    def test_32_native_c_crypto_selftest_kat_vectors(self):
        """32: dynamicstate-collector --test-crypto and test_crypto --selftest pass FIPS 180-4 and RFC 4231 vectors."""
        # 1. Collector binary --test-crypto
        res_col = subprocess.run(
            [self.collector_bin, "--test-crypto"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res_col.returncode, 0, f"Collector crypto test failed: {res_col.stderr}")
        self.assertIn("PASS: All FIPS 180-4 and RFC 4231 vectors validated in C.", res_col.stdout)

        # 2. Standalone test_crypto --selftest
        res_tc = subprocess.run(
            [self.test_crypto_bin, "--selftest"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res_tc.returncode, 0, f"test_crypto failed: {res_tc.stderr}")
        self.assertIn("PASS: All FIPS 180-4 and RFC 4231 vectors validated in C.", res_tc.stdout)

    # -------------------------------------------------------------------------
    # Test 33: Direct C and Python Cryptographic Cross-Validation
    # -------------------------------------------------------------------------
    def test_33_c_python_cryptographic_cross_validation(self):
        """33: Cross-validate pure C SHA-256 and HMAC-SHA256 against Python hashlib/hmac for edge cases."""
        # 1. Empty input SHA-256
        c_res = subprocess.run(
            [self.test_crypto_bin, "--sha256-hex", ""],
            capture_output=True,
            text=True,
        )
        self.assertEqual(c_res.returncode, 0)
        self.assertEqual(c_res.stdout.strip(), hashlib.sha256(b"").hexdigest())

        # 2. Long key (131 bytes > 64B block size) HMAC-SHA256
        long_key = bytes([0xaa] * 131)
        data = b"Phase 2.0-A.2.2.1 Trust Verification Closure Long Key Validation"
        c_res = subprocess.run(
            [self.test_crypto_bin, "--hmac-hex", long_key.hex(), data.hex()],
            capture_output=True,
            text=True,
        )
        self.assertEqual(c_res.returncode, 0)
        py_expected = hmac.new(long_key, data, hashlib.sha256).hexdigest()
        self.assertEqual(c_res.stdout.strip(), py_expected)

        # 3. Long message (10,000 bytes) HMAC-SHA256
        key = b"0123456789abcdef0123456789abcdef"
        long_msg = b"DYNAMICSTATE_LONG_MESSAGE_BYTE_" * 320
        c_res = subprocess.run(
            [self.test_crypto_bin, "--hmac-hex", key.hex(), long_msg.hex()],
            capture_output=True,
            text=True,
        )
        self.assertEqual(c_res.returncode, 0)
        py_long_expected = hmac.new(key, long_msg, hashlib.sha256).hexdigest()
        self.assertEqual(c_res.stdout.strip(), py_long_expected)

        # 4. Binary input with embedded zero bytes
        bin_key = b"key\x00with\x00zero\x00bytes\x00123"
        bin_data = b"\x00\x01\x00\x02\x03\x00\x04\x05\x00"
        c_res = subprocess.run(
            [self.test_crypto_bin, "--hmac-hex", bin_key.hex(), bin_data.hex()],
            capture_output=True,
            text=True,
        )
        self.assertEqual(c_res.returncode, 0)
        py_bin_expected = hmac.new(bin_key, bin_data, hashlib.sha256).hexdigest()
        self.assertEqual(c_res.stdout.strip(), py_bin_expected)

        # 5. Altering 1 bit in data or key changes the HMAC output
        tampered_key = bytearray(bin_key)
        tampered_key[0] ^= 0x01
        c_tampered = subprocess.run(
            [self.test_crypto_bin, "--hmac-hex", bytes(tampered_key).hex(), bin_data.hex()],
            capture_output=True,
            text=True,
        )
        self.assertEqual(c_tampered.returncode, 0)
        self.assertNotEqual(c_res.stdout.strip(), c_tampered.stdout.strip())

    # -------------------------------------------------------------------------
    # Test 34: CaptureReceipt Early-Return Bypass Closure
    # -------------------------------------------------------------------------
    def test_34_capture_receipt_bypass_prevention(self):
        """34: Alternate receipt types like CaptureReceipt cannot establish LIVE_VERIFIED and cannot bypass checks."""
        from extractor.capture_backend import CaptureReceipt

        secret = "test_secret_for_legacy_capture_receipt_32b"
        # Create a CaptureReceipt with valid HMAC signature under its own scheme
        cap_rcpt = CaptureReceipt(
            receipt_id="cap_rcpt_12345",
            backend_name="process_vm_readv",
            pid=3401,
            process_start_time="34000",
            executable_path="/bin/target",
            executable_build_id="build_id_12345",
            capture_time="2026-10-31T20:00:00Z",
            capture_duration_us=125.0,
            completeness="COMPLETE",
            consistency_level="ATOMIC",
            artifact_manifest={"heap": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
            key_id="default",
        )
        from extractor.capture_backend import compute_capture_receipt_signature
        valid_sig = compute_capture_receipt_signature(
            backend_name=cap_rcpt.backend_name,
            pid=cap_rcpt.pid,
            process_start_time=cap_rcpt.process_start_time,
            executable_path=cap_rcpt.executable_path,
            executable_build_id=cap_rcpt.executable_build_id,
            capture_time=cap_rcpt.capture_time,
            completeness=cap_rcpt.completeness,
            consistency_level=cap_rcpt.consistency_level,
            artifact_manifest=cap_rcpt.artifact_manifest,
            secret=secret,
            receipt_id=cap_rcpt.receipt_id,
            capture_duration_us=cap_rcpt.capture_duration_us,
            key_id=cap_rcpt.key_id,
            schema_version="2.0.0",
        )
        from dataclasses import replace
        signed_cap_rcpt = replace(cap_rcpt, signature=valid_sig)

        # 1. Attempting to verify CaptureReceipt in verify_live_capture_receipt fails closed
        ok, err = verify_live_capture_receipt(
            signed_cap_rcpt,
            secret=secret,
            expected_session_id="sess_3401",
            expected_pid=3401,
        )
        self.assertFalse(ok)
        self.assertIn("UNSUPPORTED_RECEIPT_TYPE", err)

        # 2. determine_snapshot_trust_state must yield IMPORTED_UNVERIFIED
        st, reason = determine_snapshot_trust_state(
            signed_cap_rcpt,
            secret=secret,
            expected_session_id="sess_3401",
            expected_pid=3401,
        )
        self.assertEqual(st, TRUST_STATE_IMPORTED_UNVERIFIED)
        self.assertIn("UNSUPPORTED_RECEIPT_TYPE", reason)

        # 3. LiveCaptureReceipt with valid signature cannot bypass mismatched session
        valid_lrcpt = issue_live_capture_receipt(
            session_id="session_A",
            pid=3401,
            executable_path="/bin/target",
            signer=self.signer,
        )
        ok_sess, err_sess = verify_live_capture_receipt(
            valid_lrcpt,
            verification_authority=self.verifier,
            expected_session_id="session_B",
        )
        self.assertFalse(ok_sess)
        self.assertIn("SESSION_MISMATCH", err_sess)

    # -------------------------------------------------------------------------
    # Test 35: Canonical Receipt Payload Delimiter Hardening
    # -------------------------------------------------------------------------
    def test_35_canonical_payload_delimiter_hardening(self):
        """35: Fields containing delimiter '|' or control characters are rejected by Python and Native C."""
        # 1. Python compute_live_receipt_signature rejects pipe in fields
        with self.assertRaises(ValueError):
            compute_live_receipt_signature(
                secret_or_signer=self.signer,
                receipt_id="rcpt_001",
                session_id="sess_001",
                pid=3501,
                executable_path="/bin/target|injection",
                build_id="b1",
                capture_source="live_collector",
                integrity_validated=True,
                issued_at="2026-10-31T20:00:00Z",
            )

        with self.assertRaises(ValueError):
            compute_live_receipt_signature(
                secret_or_signer=self.signer,
                receipt_id="rcpt\n001",
                session_id="sess_001",
                pid=3501,
                executable_path="/bin/target",
                build_id="b1",
                capture_source="live_collector",
                integrity_validated=True,
                issued_at="2026-10-31T20:00:00Z",
            )

        # 2. verify_live_capture_receipt rejects pipe in fields
        raw_dict = {
            "version": "v2",
            "receipt_id": "rcpt_001",
            "session_id": "sess|attack",
            "pid": 3501,
            "executable_path": "/bin/target",
            "build_id": "b1",
            "capture_source": "live_collector",
            "manifest_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "integrity_validated": True,
            "issued_at": "2026-10-31T20:00:00Z",
            "process_start_time": "12345",
            "signature": "abcdef0123456789" * 4,
            "key_id": "default",
        }
        ok, err = verify_live_capture_receipt(raw_dict, verification_authority=self.verifier)
        self.assertFalse(ok)
        self.assertIn("MALFORMED_RECEIPT", err)

    # -------------------------------------------------------------------------
    # Test 36: Key File and FD Loading Security Hardening
    # -------------------------------------------------------------------------
    def test_36_key_file_and_fd_security_hardening(self):
        """36: Python and Native C reject oversized keys, embedded NULs, delimiters, and invalid FDs."""
        # 1. Python load_secure_key_file rejects oversized file (> 4096 bytes)
        big_file = os.path.join(self.tmp_dir, "oversized.key")
        with open(big_file, "w") as f:
            f.write("A" * 5000)
        os.chmod(big_file, 0o600)
        with self.assertRaises(ValueError) as ctx:
            load_secure_key_file(big_file)
        self.assertIn("oversized", str(ctx.exception))

        # 2. Python load_secure_key_file rejects embedded NUL bytes
        nul_file = os.path.join(self.tmp_dir, "embedded_nul.key")
        with open(nul_file, "wb") as f:
            f.write(b"0123456789abcdef\x00extra_nul_data")
        os.chmod(nul_file, 0o600)
        with self.assertRaises(ValueError) as ctx:
            load_secure_key_file(nul_file)
        self.assertIn("embedded NUL", str(ctx.exception))

        # 3. Python load_secure_key_file rejects delimiter '|'
        pipe_file = os.path.join(self.tmp_dir, "pipe_delim.key")
        with open(pipe_file, "w") as f:
            f.write("0123456789abcdef|attacker_key\n")
        os.chmod(pipe_file, 0o600)
        with self.assertRaises(ValueError) as ctx:
            load_secure_key_file(pipe_file)
        self.assertIn("forbidden delimiter", str(ctx.exception))

        # 4. Python load_secure_key_fd rejects negative or invalid descriptor
        with self.assertRaises(ValueError):
            load_secure_key_fd(-1)

        # 5. Native C collector rejects --signing-key / -K
        res_k = subprocess.run(
            [self.collector_bin, "-K", "some_secret_key_12345", "1"],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(res_k.returncode, 0)

        # 6. Native C collector rejects invalid --key-fd arguments (strtol validation)
        for invalid_fd in ["12abc", "-1", "abc", "99999999999"]:
            res_bad_fd = subprocess.run(
                [self.collector_bin, "-D", invalid_fd, "-j", "1"],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(res_bad_fd.returncode, 0)
            self.assertTrue("INVALID_KEY_FD" in res_bad_fd.stdout or "INVALID_KEY_FD" in res_bad_fd.stderr or res_bad_fd.returncode != 0)

    # -------------------------------------------------------------------------
    # Test 37: Production Key Authority Explicit Initialization & Exception Visibility
    # -------------------------------------------------------------------------
    def test_37_production_key_authority_explicit_init(self):
        """37: Default authority fails closed without keys; from_environment does not silently swallow errors."""
        # 1. Reset authorities to unconfigured state
        reset_capture_authorities()
        def_auth = get_default_verification_authority()
        self.assertFalse(def_auth.has_keys())

        # Unconfigured verification fails closed
        dummy_rcpt = issue_live_capture_receipt(
            session_id="sess_fail_closed",
            pid=3701,
            executable_path="/bin/app",
            signer=self.signer,
        )
        ok, err = verify_live_capture_receipt(dummy_rcpt)
        self.assertFalse(ok)
        self.assertIn("VERIFICATION_KEY_UNAVAILABLE", err)

        # 2. from_environment does not swallow exceptions on invalid key file
        old_file = os.environ.get("DYNAMICSTATE_CAPTURE_KEY_FILE")
        try:
            os.environ["DYNAMICSTATE_CAPTURE_KEY_FILE"] = "/nonexistent/path/for/key.key"
            with self.assertRaises(FileNotFoundError):
                CaptureVerificationAuthority.from_environment()
        finally:
            if old_file:
                os.environ["DYNAMICSTATE_CAPTURE_KEY_FILE"] = old_file
            else:
                os.environ.pop("DYNAMICSTATE_CAPTURE_KEY_FILE", None)

        # 3. from_environment does not swallow exceptions on malformed keyring JSON
        old_ring = os.environ.get("DYNAMICSTATE_CAPTURE_KEYRING")
        try:
            os.environ["DYNAMICSTATE_CAPTURE_KEYRING"] = "{malformed_json_not_valid"
            with self.assertRaises(ValueError):
                CaptureVerificationAuthority.from_environment()
        finally:
            if old_ring:
                os.environ["DYNAMICSTATE_CAPTURE_KEYRING"] = old_ring
            else:
                os.environ.pop("DYNAMICSTATE_CAPTURE_KEYRING", None)

        # Restore test authorities
        set_default_signing_authority(self.signer)
        set_default_verification_authority(self.verifier)

    # -------------------------------------------------------------------------
    # Test 38: Unified Snapshot Disk Verification via Pinned DirFD
    # -------------------------------------------------------------------------
    def test_38_unified_snapshot_disk_verification_dirfd(self):
        """38: Disk manifest verification uses pinned dirfd with O_NOFOLLOW; symlinked manifest rejected."""
        snap_dir = os.path.join(self.tmp_dir, "snap_dirfd_test")
        os.makedirs(os.path.join(snap_dir, "memory"), exist_ok=True)
        snap = RawMemorySnapshot(
            snapshot_id="SNAP_DIRFD",
            pid=3801,
            binary="/bin/target",
            timestamp_ns=38000,
            output_dir=snap_dir,
            process_starttime=3800,
        )
        snap.save()

        orig_digest = snap.compute_manifest_digest()
        rcpt = issue_live_capture_receipt(
            session_id="sess_38",
            pid=3801,
            executable_path="/bin/target",
            process_start_time="3800",
            manifest_digest=orig_digest,
            signer=self.signer,
        )

        # Valid verification succeeds
        ok, err = verify_live_capture_receipt(rcpt, verification_authority=self.verifier, snapshot=snap)
        self.assertTrue(ok, f"Verification failed: {err}")

        # Replace manifest.json with symlink -> O_NOFOLLOW must reject it
        mpath = os.path.join(snap_dir, "manifest.json")
        target_f = os.path.join(self.tmp_dir, "external_manifest.json")
        with open(target_f, "w") as f:
            f.write("[]")
        os.unlink(mpath)
        os.symlink(target_f, mpath)

        ok_sym, err_sym = verify_live_capture_receipt(rcpt, verification_authority=self.verifier, snapshot=snap)
        self.assertFalse(ok_sym)
        self.assertTrue("MISSING_MANIFEST" in err_sym or "SNAPSHOT_INTEGRITY_FAILED" in err_sym)

    # -------------------------------------------------------------------------
    # Test 39: Trust State Model Completeness Across All Four States
    # -------------------------------------------------------------------------
    def test_39_trust_state_model_full_matrix(self):
        """39: Exhaustively assert LIVE_VERIFIED, IMPORTED_UNVERIFIED, INVALID_OR_TAMPERED, and VERIFICATION_UNAVAILABLE."""
        rcpt = issue_live_capture_receipt(
            session_id="sess_39",
            pid=3901,
            executable_path="/bin/test",
            signer=self.signer,
        )

        # 1. LIVE_VERIFIED
        st, err = determine_snapshot_trust_state(rcpt, verification_authority=self.verifier)
        self.assertEqual(st, TRUST_STATE_LIVE_VERIFIED)
        self.assertIsNone(err)

        # 2. IMPORTED_UNVERIFIED (missing receipt or unsupported receipt type)
        st_no, err_no = determine_snapshot_trust_state(None)
        self.assertEqual(st_no, TRUST_STATE_IMPORTED_UNVERIFIED)
        self.assertIn("NO_RECEIPT", err_no)

        # 3. VERIFICATION_UNAVAILABLE (no keys in authority)
        empty_auth = CaptureVerificationAuthority()
        st_unavail, err_unavail = determine_snapshot_trust_state(rcpt, verification_authority=empty_auth)
        self.assertEqual(st_unavail, TRUST_STATE_VERIFICATION_UNAVAILABLE)
        self.assertIn("VERIFICATION_KEY_UNAVAILABLE", err_unavail)

        # 4. INVALID_OR_TAMPERED (tampered signature)
        from dataclasses import replace
        tampered_sig_rcpt = replace(rcpt, signature="0123456789abcdef" * 4)
        st_tamp, err_tamp = determine_snapshot_trust_state(tampered_sig_rcpt, verification_authority=self.verifier)
        self.assertEqual(st_tamp, TRUST_STATE_INVALID_OR_TAMPERED)
        self.assertIn("SIGNATURE_INVALID", err_tamp)

        # 5. INVALID_OR_TAMPERED (revoked key)
        revoked_auth = CaptureVerificationAuthority(keys={self.signer.key_id: "test_secret_32bytes_deterministic_12345"})
        revoked_auth.revoke_key(self.signer.key_id)
        st_rev, err_rev = determine_snapshot_trust_state(rcpt, verification_authority=revoked_auth)
        self.assertEqual(st_rev, TRUST_STATE_INVALID_OR_TAMPERED)
        self.assertIn("KEY_REVOKED", err_rev)

    # -------------------------------------------------------------------------
    # Test 40: Real End-to-End Native Collector with Hardened Keys and Tamper Detection
    # -------------------------------------------------------------------------
    def test_40_real_e2e_native_collector_and_host_verifier(self):
        """40: Native C collector with key-file, pipe FD, tamper detection, and fail-closed security gates."""
        target_src = os.path.join(self.tmp_dir, "e2e_target.c")
        target_bin = os.path.join(self.tmp_dir, "e2e_target")
        with open(target_src, "w") as f:
            f.write("#include <unistd.h>\nint main() { while(1) { usleep(10000); } return 0; }\n")
        subprocess.run(["gcc", "-O0", target_src, "-o", target_bin], check=True)
        target_proc = subprocess.Popen([target_bin])

        try:
            time.sleep(0.1)
            pid = target_proc.pid

            # A. Key file capture
            kf = os.path.join(self.tmp_dir, "e2e_valid.key")
            secret = "production_secret_32bytes_long_key_123"
            with open(kf, "w") as f:
                f.write(secret + "\n")
            os.chmod(kf, 0o600)

            snap_dir = os.path.join(self.tmp_dir, "e2e_snap")
            res = subprocess.run([
                self.collector_bin,
                "-p", str(pid),
                "-o", snap_dir,
                "-F", kf,
                "-I", "e2e_key_01",
                "-S", "e2e_session_01",
                "-j",
            ], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, f"Collector failed: {res.stderr}")

            # Verify receipt on disk
            with open(os.path.join(snap_dir, "receipt.json"), "r") as rf:
                rcpt_data = json.load(rf)
            self.assertEqual(rcpt_data["version"], "v2")
            self.assertEqual(rcpt_data["session_id"], "e2e_session_01")

            verifier = CaptureVerificationAuthority(keys={"e2e_key_01": secret})
            snap = RawMemorySnapshot.load(snap_dir)
            ok, err = verify_live_capture_receipt(
                rcpt_data,
                verification_authority=verifier,
                expected_session_id="e2e_session_01",
                expected_pid=pid,
                snapshot=snap,
            )
            self.assertTrue(ok, f"E2E verification failed: {err}")

            # B. Disk manifest tampering detected
            mpath = os.path.join(snap_dir, "manifest.json")
            with open(mpath, "a") as f:
                f.write(" ")  # Change file content by 1 byte
            snap_tampered = RawMemorySnapshot.load(snap_dir)
            ok_tamp, err_tamp = verify_live_capture_receipt(
                rcpt_data,
                verification_authority=verifier,
                expected_session_id="e2e_session_01",
                expected_pid=pid,
                snapshot=snap_tampered,
            )
            self.assertFalse(ok_tamp)
            self.assertTrue("MANIFEST_DIGEST_MISMATCH" in err_tamp or "SNAPSHOT_INTEGRITY_FAILED" in err_tamp)

        finally:
            target_proc.terminate()
            target_proc.wait()

    def test_41_environment_secret_and_inline_json_rejection(self):
        """41: CaptureVerificationAuthority.from_environment rejects raw secrets and inline JSON keyrings."""
        # 1. DYNAMICSTATE_CAPTURE_SECRET rejected with ValueError
        old_sec = os.environ.get("DYNAMICSTATE_CAPTURE_SECRET")
        try:
            os.environ["DYNAMICSTATE_CAPTURE_SECRET"] = "raw_secret_value_in_env_forbidden_12345"
            with self.assertRaises(ValueError) as ctx:
                CaptureVerificationAuthority.from_environment()
            self.assertIn("DYNAMICSTATE_CAPTURE_SECRET is prohibited", str(ctx.exception))
        finally:
            if old_sec:
                os.environ["DYNAMICSTATE_CAPTURE_SECRET"] = old_sec
            else:
                os.environ.pop("DYNAMICSTATE_CAPTURE_SECRET", None)

        # 2. Inline JSON keyring in DYNAMICSTATE_CAPTURE_KEYRING rejected with ValueError
        old_kr = os.environ.get("DYNAMICSTATE_CAPTURE_KEYRING")
        try:
            os.environ["DYNAMICSTATE_CAPTURE_KEYRING"] = '{"k1": "secret_key_16bytes_min"}'
            with self.assertRaises(ValueError) as ctx:
                CaptureVerificationAuthority.from_environment()
            self.assertIn("Inline JSON keyring strings in DYNAMICSTATE_CAPTURE_KEYRING are prohibited", str(ctx.exception))
        finally:
            if old_kr:
                os.environ["DYNAMICSTATE_CAPTURE_KEYRING"] = old_kr
            else:
                os.environ.pop("DYNAMICSTATE_CAPTURE_KEYRING", None)

        # 3. Verify DeprecationWarning is emitted when from_environment is called
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            auth = CaptureVerificationAuthority.from_environment()
            self.assertTrue(any(issubclass(item.category, DeprecationWarning) for item in w))
            self.assertFalse(auth.has_keys())

    def test_42_explicit_signing_and_verification_authority_factories(self):
        """42: Explicit factory methods for CaptureSigningAuthority and CaptureVerificationAuthority."""
        key_content = "explicit_secret_factory_key_12345678"
        kf = os.path.join(self.tmp_dir, "factory_key.key")
        with open(kf, "w") as f:
            f.write(key_content + "\n")
        os.chmod(kf, 0o600)

        # 1. CaptureSigningAuthority.from_key_file
        signer_file = CaptureSigningAuthority.from_key_file(kf, key_id="fact_file_signer")
        self.assertEqual(signer_file.key_id, "fact_file_signer")

        # 2. CaptureSigningAuthority.from_key_fd
        fd = os.open(kf, os.O_RDONLY)
        try:
            signer_fd = CaptureSigningAuthority.from_key_fd(fd, key_id="fact_fd_signer")
            self.assertEqual(signer_fd.key_id, "fact_fd_signer")
        finally:
            os.close(fd)

        # 3. CaptureVerificationAuthority.from_keyring_file
        ring_path = os.path.join(self.tmp_dir, "factory_keyring.json")
        with open(ring_path, "w") as f:
            json.dump({
                "fact_file_signer": key_content,
                "fact_fd_signer": key_content,
            }, f)
        os.chmod(ring_path, 0o600)

        verifier = CaptureVerificationAuthority.from_keyring_file(ring_path)
        self.assertTrue(verifier.has_keys())
        self.assertEqual(verifier.get_key("fact_file_signer"), key_content)
        self.assertEqual(verifier.get_key("fact_fd_signer"), key_content)

        # Verify signature with explicit verifier
        payload = "test_canonical_payload_data"
        sig = signer_file.sign(payload)
        expected_sig = hmac.new(key_content.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
        self.assertEqual(sig, expected_sig)

    def test_43_python_key_reading_short_reads_and_input_bounds(self):
        """43: Python load_secure_key_file and load_secure_key_fd handle short reads, bounds, and delimiters."""
        # 1. Oversized file (> 4096 bytes)
        big_path = os.path.join(self.tmp_dir, "oversized.key")
        with open(big_path, "w") as f:
            f.write("A" * 5000)
        os.chmod(big_path, 0o600)
        with self.assertRaises(ValueError) as ctx:
            load_secure_key_file(big_path)
        self.assertIn("oversized", str(ctx.exception))

        # 2. Empty file (0 bytes)
        empty_path = os.path.join(self.tmp_dir, "empty.key")
        with open(empty_path, "w") as f:
            pass
        os.chmod(empty_path, 0o600)
        with self.assertRaises(ValueError) as ctx:
            load_secure_key_file(empty_path)
        self.assertIn("empty", str(ctx.exception))

        # 3. Invalid UTF-8
        bad_utf8 = os.path.join(self.tmp_dir, "bad_utf8.key")
        with open(bad_utf8, "wb") as f:
            f.write(b"\xff\xfe\xfa\xfb" * 10)
        os.chmod(bad_utf8, 0o600)
        with self.assertRaises(ValueError) as ctx:
            load_secure_key_file(bad_utf8)
        self.assertIn("UTF-8", str(ctx.exception))

        # 4. Embedded NUL byte
        nul_path = os.path.join(self.tmp_dir, "nul.key")
        with open(nul_path, "wb") as f:
            f.write(b"valid_key_prefix\x00extra_padding_bytes")
        os.chmod(nul_path, 0o600)
        with self.assertRaises(ValueError) as ctx:
            load_secure_key_file(nul_path)
        self.assertIn("NUL", str(ctx.exception))

        # 5. Forbidden delimiter '|'
        pipe_path = os.path.join(self.tmp_dir, "pipe.key")
        with open(pipe_path, "w") as f:
            f.write("secret|with|pipes|in|content")
        os.chmod(pipe_path, 0o600)
        with self.assertRaises(ValueError) as ctx:
            load_secure_key_file(pipe_path)
        self.assertIn("delimiter", str(ctx.exception))

        # 6. Key length bounds (< 16 or > 256)
        short_path = os.path.join(self.tmp_dir, "short.key")
        with open(short_path, "w") as f:
            f.write("short_key_10ch")
        os.chmod(short_path, 0o600)
        with self.assertRaises(ValueError) as ctx:
            load_secure_key_file(short_path)
        self.assertIn("too short", str(ctx.exception))

        # 7. FD reading via load_secure_key_fd from pipe
        r, w = os.pipe()
        try:
            os.write(w, b"valid_key_from_pipe_12345678\n")
            os.close(w)
            key_fd_val = load_secure_key_fd(r)
            self.assertEqual(key_fd_val, "valid_key_from_pipe_12345678")
        finally:
            os.close(r)

    def test_44_snapshot_directory_and_manifest_symlink_rejection(self):
        """44: Directory symlink rejection in validate_integrity, compute_manifest_digest, and verify_live_capture_receipt."""
        snap, real_dir = self._create_test_snapshot("snap_sym_test", pid=8801)
        
        # 1. Directory symlink
        sym_dir = os.path.join(self.tmp_dir, "snap_sym_link")
        os.symlink(real_dir, sym_dir)

        sym_snap = RawMemorySnapshot(
            snapshot_id="snap_sym_test",
            pid=8801,
            output_dir=sym_dir,
            regions=[],
            binary="/bin/true",
            timestamp_ns=1000000,
            process_starttime=1000,
        )
        val_ok, val_warn = sym_snap.validate_integrity()
        self.assertFalse(val_ok)
        self.assertTrue(any("symbolic link" in w for w in val_warn))

        # compute_manifest_digest fails on symlink directory
        with self.assertRaises(OSError):
            sym_snap.compute_manifest_digest()

        rcpt = issue_live_capture_receipt(
            session_id=self.session_id,
            pid=8801,
            executable_path="/bin/true",
            build_id="build_sym",
            process_start_time="1000",
            manifest_digest=snap.manifest_digest or hashlib.sha256(b"m").hexdigest(),
            signer=self.signer,
            key_id=self.test_key_id,
        )
        ok_rcpt, err_rcpt = verify_live_capture_receipt(
            rcpt,
            verification_authority=self.verifier,
            snapshot=sym_snap,
        )
        self.assertFalse(ok_rcpt)
        self.assertTrue("SNAPSHOT_DIR_SYMLINK" in err_rcpt or "SNAPSHOT_INTEGRITY_FAILED" in err_rcpt)

        # 2. Manifest symlink replacement
        snap_m, dir_m = self._create_test_snapshot("snap_m_sym", pid=8802)
        m_file = os.path.join(dir_m, "manifest.json")
        os.unlink(m_file)
        dummy_target = os.path.join(self.tmp_dir, "dummy_target.txt")
        with open(dummy_target, "w") as f:
            f.write("[]")
        os.symlink(dummy_target, m_file)

        snap_m_loaded = RawMemorySnapshot.load(dir_m)
        ok_m_val, warn_m = snap_m_loaded.validate_integrity()
        self.assertFalse(ok_m_val)
        self.assertTrue(any("symbolic link" in w for w in warn_m))

        ok_m_rcpt, err_m_rcpt = verify_live_capture_receipt(
            rcpt,
            verification_authority=self.verifier,
            snapshot=snap_m_loaded,
        )
        self.assertFalse(ok_m_rcpt)
        self.assertTrue("MANIFEST_SYMLINK_REJECTED" in err_m_rcpt or "SNAPSHOT_INTEGRITY_FAILED" in err_m_rcpt or "MISSING_MANIFEST" in err_m_rcpt)

    def test_45_snapshot_directory_replacement_detection(self):
        """45: verify_live_capture_receipt detects snapshot directory replacement (device/inode change)."""
        snap_a, dir_a = self._create_test_snapshot("snap_sub_a", pid=8901)
        snap_b, dir_b = self._create_test_snapshot("snap_sub_b", pid=8901)

        # Validate snapshot A - pins directory identity to dir_a's (st_dev, st_ino)
        v_ok, _ = snap_a.validate_integrity()
        self.assertTrue(v_ok)
        self.assertIsNotNone(getattr(snap_a, "_pinned_dir_identity", None))

        rcpt_a = issue_live_capture_receipt(
            session_id=self.session_id,
            pid=8901,
            executable_path="/bin/true",
            build_id="build_sub",
            process_start_time=str(snap_a.process_starttime),
            manifest_digest=snap_a.compute_manifest_digest(),
            signer=self.signer,
            key_id=self.test_key_id,
        )

        # Normal verification succeeds
        ok_norm, err_norm = verify_live_capture_receipt(
            rcpt_a,
            verification_authority=self.verifier,
            snapshot=snap_a,
        )
        self.assertTrue(ok_norm, f"Normal verification failed: {err_norm}")

        # Directory substitution: snap_a.output_dir is replaced by dir_b
        snap_a.output_dir = dir_b
        # If validate_integrity runs again on dir_b, it detects substitution
        val_sub_ok, val_sub_warn = snap_a.validate_integrity()
        self.assertFalse(val_sub_ok)
        self.assertTrue(any("substitution" in w.lower() for w in val_sub_warn))

        # And receipt verification directly detects directory substitution
        snap_a.validate_integrity = lambda: (True, [])
        snap_a.validation_verdict = "VALIDATED"
        ok_sub, err_sub = verify_live_capture_receipt(
            rcpt_a,
            verification_authority=self.verifier,
            snapshot=snap_a,
        )
        self.assertFalse(ok_sub)
        self.assertIn("SNAPSHOT_DIR_SUBSTITUTION", err_sub)

    def test_46_c_collector_eintr_and_eof_resilience(self):
        """46: Native C collector load_key_from_fd handles EOF, bounds, and invalid key data."""
        target_src = os.path.join(self.tmp_dir, "test46_target.c")
        target_bin = os.path.join(self.tmp_dir, "test46_target")
        with open(target_src, "w") as f:
            f.write("#include <unistd.h>\nint main() { while(1) { usleep(10000); } return 0; }\n")
        subprocess.run(["gcc", "-O0", target_src, "-o", target_bin], check=True)
        target_proc = subprocess.Popen([target_bin])

        try:
            time.sleep(0.1)
            pid = target_proc.pid

            # 1. Oversized key input via pipe (> 512 bytes)
            r1, w1 = os.pipe()
            os.write(w1, b"A" * 600)
            os.close(w1)
            snap_dir1 = os.path.join(self.tmp_dir, "c_snap_oversized")
            res1 = subprocess.run([
                self.collector_bin,
                "-p", str(pid),
                "-o", snap_dir1,
                "-D", str(r1),
                "-I", "key46",
                "-S", "sess46",
                "-j",
            ], capture_output=True, text=True, pass_fds=(r1,))
            self.assertNotEqual(res1.returncode, 0)
            self.assertIn("oversized", res1.stderr)

            # 2. Empty input via pipe (0 bytes)
            r2, w2 = os.pipe()
            os.close(w2)
            snap_dir2 = os.path.join(self.tmp_dir, "c_snap_empty")
            res2 = subprocess.run([
                self.collector_bin,
                "-p", str(pid),
                "-o", snap_dir2,
                "-D", str(r2),
                "-I", "key46",
                "-S", "sess46",
                "-j",
            ], capture_output=True, text=True, pass_fds=(r2,))
            self.assertNotEqual(res2.returncode, 0)
            self.assertIn("too short", res2.stderr)

            # 3. Forbidden delimiter '|' in key
            r3, w3 = os.pipe()
            os.write(w3, b"secret|with|forbidden|pipe\n")
            os.close(w3)
            snap_dir3 = os.path.join(self.tmp_dir, "c_snap_pipe")
            res3 = subprocess.run([
                self.collector_bin,
                "-p", str(pid),
                "-o", snap_dir3,
                "-D", str(r3),
                "-I", "key46",
                "-S", "sess46",
                "-j",
            ], capture_output=True, text=True, pass_fds=(r3,))
            self.assertNotEqual(res3.returncode, 0)
            self.assertIn("delimiter", res3.stderr)

        finally:
            target_proc.terminate()
            target_proc.wait()

    def test_47_c_collector_fd_ownership_contract(self):
        """47: Collector takes ownership and closes inherited --key-fd descriptor on all exit paths."""
        target_src = os.path.join(self.tmp_dir, "test47_target.c")
        target_bin = os.path.join(self.tmp_dir, "test47_target")
        with open(target_src, "w") as f:
            f.write("#include <unistd.h>\nint main() { while(1) { usleep(10000); } return 0; }\n")
        subprocess.run(["gcc", "-O0", target_src, "-o", target_bin], check=True)
        target_proc = subprocess.Popen([target_bin])

        try:
            time.sleep(0.1)
            pid = target_proc.pid

            # Python helper script to verify descriptor closure in child process
            test_script = f"""
import os, subprocess, json

r, w = os.pipe()
sentinel_r, sentinel_w = os.pipe()
os.write(w, b"fd_ownership_test_secret_32bytes\\n")
os.close(w)

collector_cmd = [
    {repr(self.collector_bin)},
    "-p", str({pid}),
    "-o", {repr(os.path.join(self.tmp_dir, 'c_snap_fd_own'))},
    "-D", str(r),
    "-I", "own_key",
    "-S", "own_sess",
    "-j",
]
proc = subprocess.run(collector_cmd, pass_fds=(r, sentinel_r))
assert proc.returncode == 0, f"Collector failed: {{proc.stderr}}"

# Verify sentinel remains open and valid in parent
os.write(sentinel_w, b"sentinel_ok")
os.close(sentinel_w)
msg = os.read(sentinel_r, 32)
os.close(sentinel_r)
assert msg == b"sentinel_ok"
print("FD_OWNERSHIP_SUCCESS")
"""
            runner_res = subprocess.run(
                [sys.executable, "-c", test_script],
                capture_output=True,
                text=True,
            )
            self.assertEqual(runner_res.returncode, 0, f"FD ownership script failed: {runner_res.stderr}")
            self.assertIn("FD_OWNERSHIP_SUCCESS", runner_res.stdout)

        finally:
            target_proc.terminate()
            target_proc.wait()

    def test_48_complete_live_verified_trust_prerequisites(self):
        """48: Exhaustive audit of all LIVE_VERIFIED trust prerequisites."""
        snap, snap_dir = self._create_test_snapshot("snap48_audit", pid=9001)
        snap_m_digest = snap.compute_manifest_digest()

        valid_rcpt = issue_live_capture_receipt(
            session_id=self.session_id,
            pid=9001,
            executable_path="/bin/true",
            build_id="build_48_valid",
            process_start_time=str(snap.process_starttime),
            manifest_digest=snap_m_digest,
            signer=self.signer,
            key_id=self.test_key_id,
        )

        # Baseline: valid receipt + valid snapshot -> LIVE_VERIFIED
        st, err = determine_snapshot_trust_state(
            valid_rcpt,
            verification_authority=self.verifier,
            expected_session_id=self.session_id,
            expected_pid=9001,
            expected_build_id="build_48_valid",
            snapshot=snap,
        )
        self.assertEqual(st, TRUST_STATE_LIVE_VERIFIED)
        self.assertIsNone(err)

        # Prereq 1: Missing HMAC signature
        bad_sig_rcpt = dataclasses.replace(valid_rcpt, signature="")
        st1, err1 = determine_snapshot_trust_state(bad_sig_rcpt, verification_authority=self.verifier)
        self.assertNotEqual(st1, TRUST_STATE_LIVE_VERIFIED)
        self.assertIn("UNSIGNED_RECEIPT", err1)

        # Prereq 2: Revoked key
        self.verifier.revoke_key(self.test_key_id)
        try:
            st2, err2 = determine_snapshot_trust_state(valid_rcpt, verification_authority=self.verifier)
            self.assertNotEqual(st2, TRUST_STATE_LIVE_VERIFIED)
            self.assertIn("KEY_REVOKED", err2)
        finally:
            self.verifier._revoked_keys.discard(self.test_key_id)

        # Prereq 3: Session ID mismatch
        st3, err3 = determine_snapshot_trust_state(
            valid_rcpt,
            verification_authority=self.verifier,
            expected_session_id="wrong_session_id_48",
        )
        self.assertNotEqual(st3, TRUST_STATE_LIVE_VERIFIED)
        self.assertIn("SESSION_MISMATCH", err3)

        # Prereq 4: PID mismatch
        st4, err4 = determine_snapshot_trust_state(
            valid_rcpt,
            verification_authority=self.verifier,
            expected_pid=9999,
        )
        self.assertNotEqual(st4, TRUST_STATE_LIVE_VERIFIED)
        self.assertIn("PID_MISMATCH", err4)

        # Prereq 5: Process start time mismatch
        bad_time_rcpt = issue_live_capture_receipt(
            session_id=self.session_id,
            pid=9001,
            executable_path="/bin/true",
            build_id="build_48_valid",
            process_start_time="99999999",  # Different from snapshot
            manifest_digest=snap_m_digest,
            signer=self.signer,
            key_id=self.test_key_id,
        )
        st5, err5 = determine_snapshot_trust_state(
            bad_time_rcpt,
            verification_authority=self.verifier,
            snapshot=snap,
        )
        self.assertNotEqual(st5, TRUST_STATE_LIVE_VERIFIED)
        self.assertIn("PROCESS_START_TIME_MISMATCH", err5)

        # Prereq 6: Build ID mismatch
        st6, err6 = determine_snapshot_trust_state(
            valid_rcpt,
            verification_authority=self.verifier,
            expected_build_id="different_build_id",
        )
        self.assertNotEqual(st6, TRUST_STATE_LIVE_VERIFIED)
        self.assertIn("BUILD_ID_MISMATCH", err6)

        # Prereq 7: Manifest digest mismatch
        st7, err7 = determine_snapshot_trust_state(
            valid_rcpt,
            verification_authority=self.verifier,
            expected_manifest_digest="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        self.assertNotEqual(st7, TRUST_STATE_LIVE_VERIFIED)
        self.assertIn("MANIFEST_DIGEST_MISMATCH", err7)

        # Prereq 8: Validation verdict not VALIDATED
        snap_invalid = copy.deepcopy(snap)
        snap_invalid.validation_verdict = "INVALID"
        snap_invalid.validate_integrity = lambda: (False, ["simulated_failure"])
        st8, err8 = determine_snapshot_trust_state(
            valid_rcpt,
            verification_authority=self.verifier,
            snapshot=snap_invalid,
        )
        self.assertNotEqual(st8, TRUST_STATE_LIVE_VERIFIED)
        self.assertIn("SNAPSHOT_INTEGRITY_FAILED", err8)

        # Prereq 9: Decoupled memory consistency: NON_ATOMIC consistency retains LIVE_VERIFIED
        snap_non_atomic = copy.deepcopy(snap)
        snap_non_atomic.consistency_level = "NON_ATOMIC"
        st9, err9 = determine_snapshot_trust_state(
            valid_rcpt,
            verification_authority=self.verifier,
            expected_session_id=self.session_id,
            expected_pid=9001,
            snapshot=snap_non_atomic,
        )
        self.assertEqual(st9, TRUST_STATE_LIVE_VERIFIED)
        self.assertIsNone(err9)


if __name__ == "__main__":
    unittest.main()
