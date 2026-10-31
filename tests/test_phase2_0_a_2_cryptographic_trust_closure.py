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
import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
import time
import unittest
import uuid
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
    create_receipt_from_snapshot,
    get_default_signing_authority,
    get_default_verification_authority,
    issue_live_capture_receipt,
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

        # Compile collector binary if needed
        res = subprocess.run(["make", "-C", cls.collector_dir], capture_output=True, text=True)
        if res.returncode != 0:
            raise RuntimeError(f"Failed to build dynamicstate-collector: {res.stderr}")

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="test_a2_trust_closure_")
        self.test_key_id = "test_key_phase2_0_a2_prod"
        self.test_secret = "4f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a"
        self.signer = CaptureSigningAuthority(key_id=self.test_key_id, secret=self.test_secret)
        self.verifier = CaptureVerificationAuthority(keys={self.test_key_id: self.test_secret, "default": self.test_secret})
        set_default_signing_authority(self.signer)
        set_default_verification_authority(self.verifier)

    def tearDown(self):
        reset_capture_authorities()
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

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
            col_res = subprocess.run(
                [
                    self.collector_bin,
                    "-p", str(real_pid),
                    "-o", out_snap_dir,
                    "--policy", "all",
                    "--signing-key", self.test_secret,
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


if __name__ == "__main__":
    unittest.main()
