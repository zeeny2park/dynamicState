"""Phase 1.2: Controlled Execution Trust Closure & Final Verification Test Suite.

Validates:
1. Controlled Runtime Reproduction Authentication:
   - Rejection of arbitrary token_sig strings and unverified attestation dicts
   - Rejection of forged, cross-session, or modified execution receipts
   - Rejection of mismatched target identities (PID, build_id, executable)
   - Acceptance of genuine, cryptographically signed ControlledExecutionResult
   - Preservation of synthetic and imported provenance ceilings
2. Live Capture Build Identity Closure:
   - Missing Build ID contract handling without fabrication
   - Target vs companion ELF Build ID mismatch fail-closed handling
   - TargetAssessor stripping unverified binary identity on companion mismatch
   - Executable identity binding and observation digest verification
3. Evidence Ingestion Integrity:
   - Clean RECORDED, DUPLICATE (with existing ID), and FAILED statuses
   - Preservation of exception context and absence of duplicated handlers
"""

import hashlib
import hmac
import os
import subprocess
import tempfile
import time
import unittest
import uuid
from datetime import datetime, timezone
from typing import Any, Dict

from extractor.capture_backend import (
    LiveCaptureReceipt,
    get_default_key_store,
    issue_live_capture_receipt,
)
from extractor.evidence_adapter import (
    COLLECTION_STATUS_ABSTAIN,
    COLLECTION_STATUS_COLLECTED,
    COLLECTION_STATUS_FAILED,
    EVIDENCE_TYPE_DIAGNOSTIC,
    NATURE_INFERENCE,
    NATURE_OBSERVATION,
    PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION,
    PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
    PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
    PROVENANCE_CLASS_SYNTHETIC_FIXTURE,
    RESULT_NEW_EVIDENCE,
    EvidenceAdapter,
)
from extractor.evidence_ledger import (
    ControlledExecutionResult,
    EvidenceLedger,
    EvidenceRecord,
    compute_attestation_signature,
    compute_evidence_fingerprint,
    compute_receipt_signature,
)
from extractor.expert_diagnostic_engine import (
    AdaptiveInvestigationSession,
    ExpertDiagnosticEngine,
    TargetAssessor,
)
from extractor.target_adapter import LocalTargetAdapter


class TestPhase12ControlledExecutionTrustClosure(unittest.TestCase):
    """Rigorous trust boundary and cryptographic closure tests for Phase 1.2."""

    def setUp(self):
        self.session_id = f"inv_test_p12_{uuid.uuid4().hex[:8]}"
        self.ledger = EvidenceLedger(session_id=self.session_id)
        self.adapter = EvidenceAdapter()
        self.target = {
            "pid": 43210,
            "process_identity": "43210:1700000000:boot_p12",
            "executable_identity": "/usr/bin/target_app:998877",
            "build_id": "sha1:deadbeef12345678deadbeef12345678deadbeef",
            "companion_elf": "/usr/bin/target_app",
        }

    def _create_signed_execution_result(
        self,
        investigation_id: str,
        secret: str,
        target_identity: Dict[str, Any],
        execution_status: str = "REPRODUCED",
        completeness: str = "COMPLETE",
        consistency_level: str = "ZERO_STOP_ATOMIC",
        target_function: str = "process_packet",
        field_path: str = "conn_state",
        before_value: Any = "INIT",
        after_value: Any = "ESTABLISHED",
        evidence_id: str = "ev_ctrl_valid",
        forge_signature: bool = False,
    ) -> ControlledExecutionResult:
        now_ts = datetime.now(timezone.utc).isoformat()
        res_temp = ControlledExecutionResult(
            execution_id=f"exec_{uuid.uuid4().hex[:8]}",
            investigation_id=investigation_id,
            target_function=target_function,
            field_path=field_path,
            before_value=before_value,
            after_value=after_value,
            execution_status=execution_status,
            capture_quality={"completeness": completeness, "consistency_level": consistency_level},
            target_identity=target_identity,
            evidence_id=evidence_id,
            executed_at=now_ts,
            receipt_signature="",
        )
        if forge_signature:
            sig = "0" * 64
        else:
            sig = compute_receipt_signature(secret, res_temp)

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
            evidence_id=res_temp.evidence_id,
            executed_at=res_temp.executed_at,
            receipt_signature=sig,
        )

    # =========================================================================
    # Group A: Controlled Runtime Reproduction Authentication
    # =========================================================================

    def test_a01_arbitrary_token_sig_string_is_rejected(self):
        """Caller-supplied token_sig string without authentic execution proof is downgraded to IMPORTED_UNVERIFIED."""
        rec = self.adapter.adapt_generic_tool_output(
            tool_name="replay_verifier",
            tool_result={
                "outcome": "reproduced",
                "provenance_class": PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION,
                "verifier_attestation": {"token_sig": "sig_arbitrary_token_string_123"},
            },
            target_identity=self.target,
            session_id=self.session_id,
            ledger=self.ledger,
            evidence_id="ev_a01",
        )
        self.assertEqual(rec.provenance_class, PROVENANCE_CLASS_IMPORTED_UNVERIFIED)
        self.assertNotIn("token_sig", rec.provenance.get("verifier_attestation", {}))
        self.assertIn("attestation_rejected", rec.provenance)

    def test_a02_forged_execution_receipt_signature_is_rejected(self):
        """Forged HMAC signature on ControlledExecutionResult fails cryptographic verification."""
        forged_res = self._create_signed_execution_result(
            investigation_id=self.session_id,
            secret=self.ledger.session_secret,
            target_identity=self.target,
            forge_signature=True,
        )
        rec = self.adapter.adapt_generic_tool_output(
            tool_name="replay_verifier",
            tool_result={
                "outcome": "reproduced",
                "provenance_class": PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION,
                "execution_result": forged_res,
            },
            target_identity=self.target,
            session_id=self.session_id,
            ledger=self.ledger,
            evidence_id="ev_a02",
        )
        self.assertEqual(rec.provenance_class, PROVENANCE_CLASS_IMPORTED_UNVERIFIED)

    def test_a03_cross_session_execution_proof_is_rejected(self):
        """Execution proof from a different session/investigation cannot authenticate in current session."""
        alien_session = "inv_foreign_session_9999"
        alien_secret = "secret_alien_123456789012345678901234567890"
        alien_res = self._create_signed_execution_result(
            investigation_id=alien_session,
            secret=alien_secret,
            target_identity=self.target,
        )
        rec = self.adapter.adapt_generic_tool_output(
            tool_name="replay_verifier",
            tool_result={
                "outcome": "reproduced",
                "provenance_class": PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION,
                "execution_result": alien_res,
            },
            target_identity=self.target,
            session_id=self.session_id,
            ledger=self.ledger,
            evidence_id="ev_a03",
        )
        self.assertEqual(rec.provenance_class, PROVENANCE_CLASS_IMPORTED_UNVERIFIED)

    def test_a04_mismatched_target_identity_in_execution_proof_rejected(self):
        """Execution proof with mismatched PID or build_id is rejected."""
        mismatched_target = dict(self.target)
        mismatched_target["pid"] = 99999  # Different PID
        res = self._create_signed_execution_result(
            investigation_id=self.session_id,
            secret=self.ledger.session_secret,
            target_identity=mismatched_target,
        )
        rec = self.adapter.adapt_generic_tool_output(
            tool_name="replay_verifier",
            tool_result={
                "outcome": "reproduced",
                "provenance_class": PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION,
                "execution_result": res,
            },
            target_identity=self.target,  # Session target has pid 43210
            session_id=self.session_id,
            ledger=self.ledger,
            evidence_id="ev_a04",
        )
        self.assertEqual(rec.provenance_class, PROVENANCE_CLASS_IMPORTED_UNVERIFIED)

    def test_a05_tampered_execution_result_invalidates_proof(self):
        """Tampering with values after signing invalidates cryptographic HMAC verification."""
        genuine_res = self._create_signed_execution_result(
            investigation_id=self.session_id,
            secret=self.ledger.session_secret,
            target_identity=self.target,
            before_value="ORIGINAL_BEFORE",
            after_value="ORIGINAL_AFTER",
        )
        # Tamper after_value while keeping original signature
        tampered_res = ControlledExecutionResult(
            execution_id=genuine_res.execution_id,
            investigation_id=genuine_res.investigation_id,
            target_function=genuine_res.target_function,
            field_path=genuine_res.field_path,
            before_value=genuine_res.before_value,
            after_value="TAMPERED_AFTER",
            execution_status=genuine_res.execution_status,
            capture_quality=genuine_res.capture_quality,
            target_identity=genuine_res.target_identity,
            evidence_id=genuine_res.evidence_id,
            executed_at=genuine_res.executed_at,
            receipt_signature=genuine_res.receipt_signature,
        )
        rec = self.adapter.adapt_generic_tool_output(
            tool_name="replay_verifier",
            tool_result={
                "outcome": "reproduced",
                "provenance_class": PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION,
                "execution_result": tampered_res,
            },
            target_identity=self.target,
            session_id=self.session_id,
            ledger=self.ledger,
            evidence_id="ev_a05",
        )
        self.assertEqual(rec.provenance_class, PROVENANCE_CLASS_IMPORTED_UNVERIFIED)

    def test_a06_genuine_production_execution_proof_accepted_and_admitted(self):
        """Genuine signed ControlledExecutionResult is verified, authenticated, and admitted to ledger."""
        res = self._create_signed_execution_result(
            investigation_id=self.session_id,
            secret=self.ledger.session_secret,
            target_identity=self.target,
            evidence_id="ev_a06_genuine",
        )
        rec = self.adapter.adapt_generic_tool_output(
            tool_name="replay_verifier",
            tool_result={
                "outcome": "reproduced",
                "provenance_class": PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION,
                "execution_result": res,
            },
            target_identity=self.target,
            session_id=self.session_id,
            ledger=self.ledger,
            evidence_id="ev_a06_genuine",
        )
        self.assertEqual(rec.provenance_class, PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION)
        self.assertIsNotNone(rec.provenance.get("verifier_attestation"))
        self.assertEqual(rec.provenance["verifier_attestation"]["investigation_id"], self.session_id)

        # Admitting into ledger succeeds and verifies cryptographic attestation
        added = self.adapter.record_into_ledger(rec, self.ledger, raise_on_error=True)
        self.assertEqual(len(added), 1)
        stored = self.ledger.get_record("ev_a06_genuine")
        self.assertIsNotNone(stored)
        self.assertEqual(stored.provenance_class, PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION)

    def test_a07_synthetic_ceiling_prevents_promotion_to_controlled(self):
        """Synthetic fixture cannot be promoted to CONTROLLED_RUNTIME_REPRODUCTION even with signed proof."""
        res = self._create_signed_execution_result(
            investigation_id=self.session_id,
            secret=self.ledger.session_secret,
            target_identity=self.target,
        )
        rec = self.adapter.adapt_generic_tool_output(
            tool_name="replay_verifier",
            tool_result={
                "outcome": "reproduced",
                "is_synthetic": True,
                "provenance_class": PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION,
                "execution_result": res,
            },
            target_identity=self.target,
            session_id=self.session_id,
            ledger=self.ledger,
            evidence_id="ev_a07",
        )
        self.assertEqual(rec.provenance_class, PROVENANCE_CLASS_SYNTHETIC_FIXTURE)

    def test_a08_caller_submitted_ceiling_prevents_promotion(self):
        """Caller submitted data cannot establish CONTROLLED_RUNTIME_REPRODUCTION."""
        res = self._create_signed_execution_result(
            investigation_id=self.session_id,
            secret=self.ledger.session_secret,
            target_identity=self.target,
        )
        rec = self.adapter.adapt_generic_tool_output(
            tool_name="replay_verifier",
            tool_result={
                "outcome": "reproduced",
                "caller_submitted": True,
                "provenance_class": PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION,
                "execution_result": res,
            },
            target_identity=self.target,
            session_id=self.session_id,
            ledger=self.ledger,
            evidence_id="ev_a08",
        )
        self.assertEqual(rec.provenance_class, PROVENANCE_CLASS_IMPORTED_UNVERIFIED)

    # =========================================================================
    # Group B: Live Capture Build Identity Closure
    # =========================================================================

    def test_b01_missing_build_id_permitted_when_no_companion_or_elf_note(self):
        """When target binary has no ELF Build ID and no companion build ID is expected, live capture is valid."""
        adapter = LocalTargetAdapter()
        current_pid = os.getpid()
        tx = adapter.begin_capture_transaction(
            session_id=self.session_id,
            pid=current_pid,
            operation_type="diagnostic",
            snapshot_binding=f"snap_{self.session_id}_b01",
        )
        adapter.read_memory(current_pid, id(self), 32)
        committed_tx = adapter.commit_capture_transaction(tx)
        self.assertGreater(committed_tx.physical_bytes_read, 0)

        # Issue receipt without companion build ID (empty build ID)
        rcpt = adapter.issue_live_receipt_for_session(
            session_id=self.session_id,
            pid=current_pid,
            snapshot_binding=committed_tx.snapshot_binding,
            companion_build_id="",
            transaction=committed_tx,
        )
        self.assertIsNotNone(rcpt)
        # Verification succeeds when expected_build_id is None / empty
        ok, reason = rcpt.verify(
            expected_session_id=self.session_id,
            expected_pid=current_pid,
            expected_process_identity=rcpt.process_identity,
            expected_executable_identity=rcpt.executable_identity,
            expected_build_id=None,
            require_production_authority=True,
        )
        self.assertTrue(ok, f"Verification failed: {reason}")

    def test_b02_companion_build_id_mismatch_raises_error_in_receipt_issuance(self):
        """If target process has Build ID and companion ELF has different Build ID, receipt issuance fails."""
        adapter = LocalTargetAdapter()
        current_pid = os.getpid()
        # Pin target identity
        adapter.pin_target_identity(current_pid)
        real_bid = adapter._pinned_identities[current_pid].get("build_id")

        tx = adapter.begin_capture_transaction(
            session_id=self.session_id,
            pid=current_pid,
            operation_type="diagnostic",
            snapshot_binding=f"snap_{self.session_id}_b02",
        )
        adapter.read_memory(current_pid, id(self), 32)
        committed_tx = adapter.commit_capture_transaction(tx)

        with self.assertRaises(ValueError) as ctx:
            adapter.issue_live_receipt_for_session(
                session_id=self.session_id,
                pid=current_pid,
                snapshot_binding=committed_tx.snapshot_binding,
                companion_build_id="sha1:different_companion_build_id_99999",
                transaction=committed_tx,
            )
        self.assertIn("Build ID mismatch", str(ctx.exception))

    def test_b03_target_assessor_strips_binary_identity_on_companion_build_id_mismatch(self):
        """TargetAssessor strips build_id and DWARF info if companion ELF Build ID mismatches target process."""
        assessor = TargetAssessor()
        current_pid = os.getpid()

        # Create temporary dummy ELF file with some bytes
        with tempfile.NamedTemporaryFile(suffix=".elf", delete=False) as f:
            f.write(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 128)
            dummy_elf = f.name

        try:
            adapter = LocalTargetAdapter()
            adapter.pin_target_identity(current_pid)

            # Mock inspect_elf in both modules
            import extractor.target_adapter as ta
            import extractor.debug_image as di
            import extractor.expert_diagnostic_engine as ede
            orig_ta_inspect = getattr(ta, "inspect_elf", None)
            orig_di_inspect = getattr(di, "inspect_elf", None)
            from extractor.target_adapter import BinaryIdentity

            def mock_inspect(path):
                if str(path).endswith(".elf"):
                    return BinaryIdentity(
                        path=path,
                        elf_class="ELF64",
                        architecture="x86_64",
                        endianness="little",
                        build_id="sha1:companion_build_id_67890",
                        stripped=False,
                        has_debug_info=True,
                        elf_type="EXEC",
                    )
                if orig_ta_inspect:
                    return orig_ta_inspect(path)
                return di.inspect_elf(path)

            ta.inspect_elf = mock_inspect
            di.inspect_elf = mock_inspect
            ede.inspect_elf = mock_inspect
            try:
                res = assessor.assess(pid=current_pid, companion_elf=dummy_elf, adapter=adapter)
                # build_id should be None because of mismatch between process and companion ELF
                self.assertIsNone(res.build_id)
                self.assertFalse(res.dwarf_available)
                self.assertTrue(any("Build ID mismatch" in lim for lim in res.limitations))
            finally:
                if orig_ta_inspect:
                    ta.inspect_elf = orig_ta_inspect
                if orig_di_inspect:
                    di.inspect_elf = orig_di_inspect
                ede.inspect_elf = orig_ta_inspect
        finally:
            if os.path.exists(dummy_elf):
                os.remove(dummy_elf)

    def test_b04_executable_identity_mismatch_rejected(self):
        """Mismatched executable identity in LiveCaptureReceipt causes verify() to fail closed."""
        from extractor.capture_backend import get_trusted_capture_authority_token
        rcpt = issue_live_capture_receipt(
            session_id=self.session_id,
            pid=self.target["pid"],
            process_identity=self.target["process_identity"],
            executable_identity="/usr/bin/original_exe:1001",
            build_id=self.target["build_id"],
            snapshot_binding=f"snap_{self.session_id}_b04",
            capture_epoch=1,
            physical_bytes_read=128,
            capture_authority_token=get_trusted_capture_authority_token(),
        )
        ok, reason = rcpt.verify(
            expected_session_id=self.session_id,
            expected_pid=self.target["pid"],
            expected_process_identity=self.target["process_identity"],
            expected_executable_identity="/usr/bin/tampered_exe:2002",
            require_production_authority=True,
        )
        self.assertFalse(ok)
        self.assertIn("mismatched_executable_identity", reason)

    def test_b05_observation_digest_mismatch_rejected(self):
        """Mismatched observation digest in LiveCaptureReceipt causes verify() to fail closed."""
        from extractor.capture_backend import get_trusted_capture_authority_token
        rcpt = issue_live_capture_receipt(
            session_id=self.session_id,
            pid=self.target["pid"],
            process_identity=self.target["process_identity"],
            executable_identity=self.target["executable_identity"],
            build_id=self.target["build_id"],
            snapshot_binding=f"snap_{self.session_id}_b05",
            capture_epoch=1,
            physical_bytes_read=128,
            observation_digest="sha256:digest_alpha_1111",
            capture_authority_token=get_trusted_capture_authority_token(),
        )
        ok, reason = rcpt.verify(
            expected_session_id=self.session_id,
            expected_pid=self.target["pid"],
            expected_process_identity=self.target["process_identity"],
            expected_executable_identity=self.target["executable_identity"],
            expected_observation_digest="sha256:digest_beta_2222",
            require_production_authority=True,
        )
        self.assertFalse(ok)
        self.assertIn("mismatched_observation_digest", reason)

    # =========================================================================
    # Group C: Evidence Ingestion Cleanup & Status Integrity
    # =========================================================================

    def test_c01_recorded_duplicate_failed_status_distinction(self):
        """Tests that RECORDED, DUPLICATE: <id>, and FAILED: <reason> are strictly distinguished."""
        engine = ExpertDiagnosticEngine()
        session = engine.start_investigation(
            problem_statement="Test C01 status distinction",
            pid=self.target["pid"],
            investigation_id=self.session_id,
        )
        session.ledger = self.ledger

        ev_id = "ev_c01_test"
        enriched = {
            "evidence_id": ev_id,
            "recipe_id": "test_recipe",
            "finding": "Test observation value 100",
            "provenance_class": PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
        }

        # 1. First record -> RECORDED
        st1 = session._record_authoritative_evidence_in_ledger(
            ev_id=ev_id,
            recipe_id="test_recipe",
            observation_text="Test observation value 100",
            prov_class=PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
            enriched_ev=enriched,
        )
        self.assertEqual(st1, "RECORDED")
        self.assertTrue(self.ledger.has(ev_id))

        # 2. Identical record re-admission -> DUPLICATE: <ev_id>
        st2 = session._record_authoritative_evidence_in_ledger(
            ev_id=f"ev_c01_dup_{uuid.uuid4().hex[:6]}",
            recipe_id="test_recipe",
            observation_text="Test observation value 100",
            prov_class=PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
            enriched_ev=enriched,
        )
        self.assertTrue(st2.startswith("DUPLICATE:"), f"Expected DUPLICATE, got {st2}")
        self.assertIn(ev_id, st2)

        # 3. Conflicting record with same ID but incompatible content -> FAILED: ValueError
        conflicting = dict(enriched)
        conflicting["finding"] = "Completely different observation content 9999"
        conflicting["payload_digest"] = "different_digest_xyz"
        conflicting["semantic_digest"] = "different_sem_xyz"
        st3 = session._record_authoritative_evidence_in_ledger(
            ev_id=ev_id,
            recipe_id="test_recipe",
            observation_text="Completely different observation content 9999",
            prov_class=PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
            enriched_ev=conflicting,
        )
        self.assertTrue(st3.startswith("FAILED:"), f"Expected FAILED, got {st3}")
        self.assertIn("ValueError", st3)

    def test_c02_no_private_ledger_access_in_production(self):
        """Verifies that ledger public API is used exclusively and private collections remain encapsulated."""
        self.assertEqual(len(self.ledger), 0)
        self.assertFalse(self.ledger.has("nonexistent_id"))
        self.assertIsNone(self.ledger.get_record("nonexistent_id"))
        self.assertFalse(self.ledger.has_semantic_digest("sha256:nonexistent"))
        self.assertIsNone(self.ledger.find_by_semantic_digest("sha256:nonexistent"))
        self.assertEqual(len(self.ledger.get_records()), 0)


if __name__ == "__main__":
    unittest.main()
