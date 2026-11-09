"""Phase 1.1 — Canonical Evidence Ingestion Hardening & Trust Boundary Closure.

Comprehensive test suite verifying:
1. Live Capture Receipt Trust Boundary:
   - String prov_class cannot create trusted evidence.
   - PID alone cannot create trusted evidence.
   - Forged receipt is rejected.
   - Cross-session, cross-PID, mismatched executable, and mismatched Build ID receipts are rejected.
   - Genuine receipt from the actual production capture path is accepted.
   - Synthetic and imported evidence cannot be promoted.
   - CONTROLLED_RUNTIME_REPRODUCTION is preserved, never escalated.
2. Encapsulation & Private Ledger Access Removal:
   - Zero production access to ledger._records or ledger._by_id.
   - Public semantic digest lookup (find_by_semantic_digest, has_semantic_digest).
   - Duplicate detection and fail-closed conflict rejection.
3. Target Identity & Build ID Semantics:
   - No fabricated Build IDs or process identities (no 'sha1:runtime_verified_build').
   - Serialization round-trip preserves identity attributes faithfully.
4. Evidence Semantics & Relationship Integrity:
   - source_correlation preserved.
   - Inference and hypothesis evidence never become observations.
   - Parent evidence IDs and causal links preserved.
   - Partial/failed observation statuses preserved.
"""

from datetime import datetime, timezone
import json
import os
import subprocess
import time
import unittest

from extractor.capture_backend import (
    LiveCaptureReceipt,
    get_trusted_capture_authority_token,
    issue_live_capture_receipt,
)
from extractor.evidence_adapter import (
    EvidenceAdapter,
    PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION,
    PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
    PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
    PROVENANCE_CLASS_SYNTHETIC_FIXTURE,
)
from extractor.evidence_ledger import (
    EvidenceLedger,
    EvidenceRecord,
    EVIDENCE_TYPE_DIAGNOSTIC,
    NATURE_HYPOTHESIS,
    NATURE_INFERENCE,
    NATURE_OBSERVATION,
)
from extractor.expert_diagnostic_engine import (
    AdaptiveInvestigationSession,
    ExpertDiagnosticEngine,
    TargetAssessmentResult,
    TargetAssessor,
)
from extractor.target_adapter import LocalTargetAdapter, inspect_elf


class TestPhase11HardeningAndTrustClosure(unittest.TestCase):
    """Test suite for Phase 1.1 hardening and trust boundary closure."""

    @classmethod
    def setUpClass(cls):
        cls.companion_elf = "/tmp/expert_diagnostic_debug.elf"
        cls.proc = subprocess.Popen([cls.companion_elf, "healthy"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(0.15)
        cls.pid = cls.proc.pid
        cls.target_adapter = LocalTargetAdapter()
        proc_info = cls.target_adapter.get_process_identity(cls.pid)
        cls.proc_identity = proc_info.get("process_identity")
        cls.exe_identity = proc_info.get("executable_identity") or proc_info.get("executable")
        cls.build_id = proc_info.get("build_id")

    @classmethod
    def tearDownClass(cls):
        try:
            if cls.proc.stdout:
                cls.proc.stdout.close()
            if cls.proc.stderr:
                cls.proc.stderr.close()
            cls.proc.terminate()
            cls.proc.wait(timeout=1.0)
        except Exception:
            try:
                cls.proc.kill()
            except Exception:
                pass

    def setUp(self):
        self.session_id = f"sess_p1_1_{int(time.time()*1000)}"
        self.ledger = EvidenceLedger(session_id=self.session_id)
        self.adapter = EvidenceAdapter()
        self.target = {
            "pid": self.pid,
            "process_identity": self.proc_identity,
            "executable_identity": self.exe_identity,
            "build_id": self.build_id,
            "session_id": self.session_id,
        }

    # =========================================================================
    # Part 1: Live Capture Receipt Trust Boundary
    # =========================================================================

    def test_01_string_provenance_label_cannot_create_trusted_evidence(self):
        """Passing LIVE_RUNTIME_CAPTURE as a string without a receipt must downgrade to IMPORTED_UNVERIFIED."""
        engine = ExpertDiagnosticEngine(corpus_dir="/tmp/p1_1_test_corpus")
        session = engine.start_investigation(
            problem_statement="Investigate memory without capture receipt",
            pid=self.pid,
            companion_elf=self.companion_elf,
        )

        status = session._record_authoritative_evidence_in_ledger(
            ev_id="ev_untrusted_claim",
            recipe_id="RECIPE_MEM_01",
            observation_text="Caller claims this is live",
            prov_class=PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
            enriched_ev={
                "finding": "Caller claims live without receipt",
                "finding_classification": "OBSERVED_FACT",
                "target_pid": self.pid,
            },
        )
        self.assertEqual(status, "RECORDED")
        rec = session.ledger.get_record("ev_untrusted_claim")
        self.assertIsNotNone(rec)
        # Must NOT be live capture
        self.assertEqual(rec.provenance_class, PROVENANCE_CLASS_IMPORTED_UNVERIFIED)
        self.assertNotIn("live_capture_receipt", rec.provenance)

    def test_02_pid_alone_cannot_create_trusted_evidence(self):
        """Supplying a live PID alone without a verified receipt cannot obtain LIVE_RUNTIME_CAPTURE."""
        rec = self.adapter.adapt_generic_tool_output(
            tool_name="memory_tool",
            tool_result={"raw_val": 42, "pid": self.pid},
            target_identity={"pid": self.pid},
            session_id=self.session_id,
            evidence_id="ev_pid_only",
        )
        self.assertEqual(rec.provenance_class, PROVENANCE_CLASS_IMPORTED_UNVERIFIED)
        self.assertNotIn("live_capture_receipt", rec.provenance)

    def test_03_forged_receipt_is_rejected_or_downgraded(self):
        """A forged receipt with an invalid signature cannot create trusted evidence."""
        auth_token = get_trusted_capture_authority_token()
        genuine = issue_live_capture_receipt(
            session_id=self.session_id,
            pid=self.pid,
            process_identity=self.proc_identity,
            executable_identity=self.exe_identity,
            build_id=self.build_id,
            snapshot_binding="snap_01",
            capture_authority_token=auth_token,
        )
        forged_dict = genuine.to_dict()
        forged_dict["signature"] = "deadbeef" * 8  # Forged HMAC

        rec = self.adapter.adapt_generic_tool_output(
            tool_name="memory_tool",
            tool_result={"raw_val": 42, "live_capture_receipt": forged_dict},
            target_identity=self.target,
            session_id=self.session_id,
            evidence_id="ev_forged_sig",
        )
        self.assertEqual(rec.provenance_class, PROVENANCE_CLASS_IMPORTED_UNVERIFIED)
        self.assertNotIn("live_capture_receipt", rec.provenance)

    def test_04_cross_session_receipt_rejected(self):
        """A receipt from another session must fail verification."""
        auth_token = get_trusted_capture_authority_token()
        other_session = "sess_other_999"
        receipt = issue_live_capture_receipt(
            session_id=other_session,
            pid=self.pid,
            process_identity=self.proc_identity,
            executable_identity=self.exe_identity,
            build_id=self.build_id,
            snapshot_binding="snap_01",
            capture_authority_token=auth_token,
        )

        rec = self.adapter.adapt_generic_tool_output(
            tool_name="memory_tool",
            tool_result={"raw_val": 42, "live_capture_receipt": receipt.to_dict()},
            target_identity=self.target,
            session_id=self.session_id,
            evidence_id="ev_cross_session",
        )
        self.assertEqual(rec.provenance_class, PROVENANCE_CLASS_IMPORTED_UNVERIFIED)

    def test_05_cross_pid_receipt_rejected(self):
        """A receipt from another PID must fail verification."""
        auth_token = get_trusted_capture_authority_token()
        other_pid = self.pid + 999
        receipt = issue_live_capture_receipt(
            session_id=self.session_id,
            pid=other_pid,
            process_identity=self.proc_identity,
            executable_identity=self.exe_identity,
            build_id=self.build_id,
            snapshot_binding="snap_01",
            capture_authority_token=auth_token,
        )

        rec = self.adapter.adapt_generic_tool_output(
            tool_name="memory_tool",
            tool_result={"raw_val": 42, "live_capture_receipt": receipt.to_dict()},
            target_identity=self.target,
            session_id=self.session_id,
            evidence_id="ev_cross_pid",
        )
        self.assertEqual(rec.provenance_class, PROVENANCE_CLASS_IMPORTED_UNVERIFIED)

    def test_06_mismatched_build_id_receipt_rejected(self):
        """A receipt with mismatched Build ID must be rejected."""
        auth_token = get_trusted_capture_authority_token()
        mismatched_bid = "sha1:mismatched_build_id_deadbeef"
        receipt = issue_live_capture_receipt(
            session_id=self.session_id,
            pid=self.pid,
            process_identity=self.proc_identity,
            executable_identity=self.exe_identity,
            build_id=mismatched_bid,
            snapshot_binding="snap_01",
            capture_authority_token=auth_token,
        )

        rec = self.adapter.adapt_generic_tool_output(
            tool_name="memory_tool",
            tool_result={"raw_val": 42, "live_capture_receipt": receipt.to_dict()},
            target_identity=self.target,
            session_id=self.session_id,
            evidence_id="ev_mismatched_bid",
        )
        self.assertEqual(rec.provenance_class, PROVENANCE_CLASS_IMPORTED_UNVERIFIED)

    def test_07_genuine_production_capture_path_accepted(self):
        """A genuine receipt from the actual production capture path (LocalTargetAdapter transaction) is accepted as LIVE_RUNTIME_CAPTURE."""
        adapter = LocalTargetAdapter()
        tx = adapter.begin_capture_transaction(
            session_id=self.session_id,
            pid=self.pid,
            operation_type="diagnostic",
            snapshot_binding="snap_prod_01",
        )
        maps = adapter.get_proc_maps(self.pid)
        self.assertGreater(len(maps), 0)
        first_readable = None
        for m in maps:
            if "r" in m.get("permissions", ""):
                first_readable = m.get("start_int") or int(m["start"], 16)
                break
        self.assertIsNotNone(first_readable)
        data, status, err = adapter.read_memory(self.pid, first_readable, 16)
        self.assertIsNotNone(data)
        committed = adapter.commit_capture_transaction(tx)
        self.assertGreater(committed.physical_bytes_read, 0)

        # Issue live receipt via production authority
        rcpt = adapter.issue_live_receipt_for_session(
            session_id=self.session_id,
            pid=self.pid,
            snapshot_binding=committed.snapshot_binding,
            companion_build_id=self.build_id,
            transaction=committed,
        )
        self.assertIsNotNone(rcpt)

        # Ingest through canonical adapter
        target_info = adapter.get_process_identity(self.pid)
        rec = self.adapter.adapt_generic_tool_output(
            tool_name="prod_memory_reader",
            tool_result={"raw_val": data.hex(), "live_capture_receipt": rcpt.to_dict()},
            target_identity=target_info,
            session_id=self.session_id,
            evidence_id="ev_genuine_prod_01",
        )
        self.assertEqual(rec.provenance_class, PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE)
        self.assertIn("live_capture_receipt", rec.provenance)

        # Ingest into ledger
        added = self.adapter.record_into_ledger(rec, self.ledger, raise_on_error=True)
        self.assertEqual(len(added), 1)
        ledger_rec = self.ledger.get_record("ev_genuine_prod_01")
        self.assertIsNotNone(ledger_rec)
        self.assertEqual(ledger_rec.provenance_class, PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE)

    def test_08_controlled_reproduction_not_promoted_to_live(self):
        """Controlled reproduction evidence requires genuine signed ControlledExecutionResult and is never escalated to live."""
        from extractor.evidence_ledger import ControlledExecutionResult, compute_receipt_signature
        now_ts = datetime.now(timezone.utc).isoformat()
        temp_res = ControlledExecutionResult(
            execution_id="exec_test_08",
            investigation_id=self.session_id,
            target_function="test_fn",
            field_path="test_field",
            before_value=1,
            after_value=2,
            execution_status="REPRODUCED",
            capture_quality={"completeness": "COMPLETE", "consistency_level": "ZERO_STOP_ATOMIC"},
            target_identity=self.target,
            evidence_id="ev_controlled_01",
            executed_at=now_ts,
            receipt_signature="",
        )
        sig = compute_receipt_signature(self.ledger.session_secret, temp_res)
        genuine_res = ControlledExecutionResult(
            execution_id=temp_res.execution_id,
            investigation_id=temp_res.investigation_id,
            target_function=temp_res.target_function,
            field_path=temp_res.field_path,
            before_value=temp_res.before_value,
            after_value=temp_res.after_value,
            execution_status=temp_res.execution_status,
            capture_quality=temp_res.capture_quality,
            target_identity=temp_res.target_identity,
            evidence_id=temp_res.evidence_id,
            executed_at=temp_res.executed_at,
            receipt_signature=sig,
        )

        rec = self.adapter.adapt_generic_tool_output(
            tool_name="gdb_replay",
            tool_result={
                "outcome": "reproduced",
                "provenance_class": PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION,
                "execution_result": genuine_res,
            },
            target_identity=self.target,
            session_id=self.session_id,
            ledger=self.ledger,
            evidence_id="ev_controlled_01",
        )
        self.assertEqual(rec.provenance_class, PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION)
        self.assertNotEqual(rec.provenance_class, PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE)

        # Conversely, arbitrary caller-supplied token_sig without genuine execution proof is rejected
        rec_forged = self.adapter.adapt_generic_tool_output(
            tool_name="gdb_replay",
            tool_result={
                "outcome": "reproduced",
                "provenance_class": PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION,
                "verifier_attestation": {"token_sig": "sig_valid_123"},
            },
            target_identity=self.target,
            session_id=self.session_id,
            evidence_id="ev_controlled_forged",
        )
        self.assertEqual(rec_forged.provenance_class, PROVENANCE_CLASS_IMPORTED_UNVERIFIED)

    # =========================================================================
    # Part 2: Encapsulation & Private Ledger Access Removal
    # =========================================================================

    def test_09_public_api_semantic_digest_deduplication(self):
        """Verifies duplicate recognition using public find_by_semantic_digest API."""
        rec1 = self.adapter.adapt_generic_tool_output(
            tool_name="tool_a",
            tool_result={"status": "OK", "val": 100},
            target_identity=self.target,
            session_id=self.session_id,
            evidence_id="ev_first",
        )
        self.adapter.record_into_ledger(rec1, self.ledger, raise_on_error=True)

        sem_digest = rec1.details["semantic_digest"]
        self.assertTrue(self.ledger.has_semantic_digest(sem_digest))
        found = self.ledger.find_by_semantic_digest(sem_digest)
        self.assertIsNotNone(found)
        self.assertEqual(found.evidence_id, "ev_first")

        # Second record with identical payload but different ID
        rec2 = self.adapter.adapt_generic_tool_output(
            tool_name="tool_a",
            tool_result={"status": "OK", "val": 100},
            target_identity=self.target,
            session_id=self.session_id,
            evidence_id="ev_second_dup",
        )
        added = self.adapter.record_into_ledger(rec2, self.ledger, raise_on_error=True)
        # Must be deduplicated (not added again)
        self.assertEqual(len(added), 0)
        self.assertFalse(self.ledger.has("ev_second_dup"))
        self.assertEqual(len(self.ledger), 1)

    def test_10_conflicting_id_different_content_rejected(self):
        """Registering a different observation with an existing evidence ID raises ValueError."""
        rec1 = EvidenceRecord(
            evidence_id="ev_conflict_id",
            evidence_type=EVIDENCE_TYPE_DIAGNOSTIC,
            nature=NATURE_OBSERVATION,
            observation="First observation",
            session_id=self.session_id,
            details={"semantic_digest": "digest_one"},
        )
        self.ledger.add_record(rec1)

        rec2 = EvidenceRecord(
            evidence_id="ev_conflict_id",
            evidence_type=EVIDENCE_TYPE_DIAGNOSTIC,
            nature=NATURE_OBSERVATION,
            observation="Second observation - different content",
            session_id=self.session_id,
            details={"semantic_digest": "digest_two"},
        )
        with self.assertRaises(ValueError):
            self.adapter.record_into_ledger(rec2, self.ledger, raise_on_error=True)

    def test_11_raise_on_error_propagation(self):
        """Ledger registration exceptions are propagated when raise_on_error=True and suppressed when False."""
        bad_rec = EvidenceRecord(
            evidence_id="ev_bad",
            evidence_type=EVIDENCE_TYPE_DIAGNOSTIC,
            nature=NATURE_OBSERVATION,
            provenance={"provenance_class": "INVALID_PROV_CLASS"},
            details={"provenance_class": "INVALID_PROV_CLASS"},
            session_id=self.session_id,
        )
        with self.assertRaises(ValueError):
            self.adapter.record_into_ledger(bad_rec, self.ledger, raise_on_error=True)

        # Suppressed when False
        res = self.adapter.record_into_ledger(bad_rec, self.ledger, raise_on_error=False)
        self.assertEqual(res, [])

    # =========================================================================
    # Part 3: Target Identity & Build ID Semantics
    # =========================================================================

    def test_12_no_fabricated_build_id(self):
        """Missing Build ID is preserved as None, never fabricated as 'sha1:runtime_verified_build'."""
        engine = ExpertDiagnosticEngine(corpus_dir="/tmp/p1_1_test_corpus")
        session = engine.start_investigation(
            problem_statement="Offline investigation without binary",
            pid=None,
            companion_elf=None,
        )
        status = session._record_authoritative_evidence_in_ledger(
            ev_id="ev_no_bid",
            recipe_id="RECIPE_LEAK",
            observation_text="Test observation without build ID",
            prov_class=PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
            enriched_ev={"raw_observation": {"metric": 10}},
        )
        self.assertEqual(status, "RECORDED")
        rec = session.ledger.get_record("ev_no_bid")
        self.assertIsNotNone(rec)
        t_ident = rec.target_identity or {}
        self.assertNotIn("build_id", t_ident)
        self.assertNotEqual(t_ident.get("build_id"), "sha1:runtime_verified_build")

    def test_13_target_assessment_identity_serialization(self):
        """TargetAssessmentResult correctly serializes and restores real identity fields."""
        ta = TargetAssessmentResult(
            pid=self.pid,
            accessible=True,
            thread_count=1,
            memory_regions_count=10,
            rss_kb=1024,
            companion_elf_path=self.companion_elf,
            companion_elf_valid=True,
            dwarf_available=True,
            capabilities=["PROC_FS_AVAILABLE"],
            limitations=[],
            prerequisites_met=True,
            build_id=self.build_id,
            process_identity=self.proc_identity,
            executable_identity=self.exe_identity,
        )
        d = ta.to_dict()
        self.assertEqual(d["build_id"], self.build_id)
        self.assertEqual(d["process_identity"], self.proc_identity)
        self.assertEqual(d["executable_identity"], self.exe_identity)

        engine = ExpertDiagnosticEngine(corpus_dir="/tmp/p1_1_test_corpus")
        session = engine.start_investigation(
            problem_statement="Target identity test",
            pid=self.pid,
            companion_elf=self.companion_elf,
        )
        session.target_assessment = ta
        sess_dict = session.to_dict()
        restored = AdaptiveInvestigationSession.from_dict(sess_dict)
        self.assertIsNotNone(restored.target_assessment)
        self.assertEqual(restored.target_assessment.build_id, self.build_id)
        self.assertEqual(restored.target_assessment.process_identity, self.proc_identity)
        self.assertEqual(restored.target_assessment.executable_identity, self.exe_identity)

    # =========================================================================
    # Part 4: Preserve Evidence Semantics and Relationships
    # =========================================================================

    def test_14_source_correlation_preserved(self):
        """source_correlation is preserved in details and static_code_link."""
        corr = {"file": "engine.cpp", "line": 150, "function": "process_request"}
        rec = self.adapter.adapt_generic_tool_output(
            tool_name="recipe_analyzer",
            tool_result={
                "finding": "Dangling pointer detected",
                "source_correlation": corr,
            },
            target_identity=self.target,
            session_id=self.session_id,
            evidence_id="ev_corr_test",
        )
        self.assertEqual(rec.details.get("source_correlation"), corr)
        self.assertEqual(rec.details.get("correlation"), corr)
        self.assertEqual(rec.static_code_link, corr)

    def test_15_inferences_and_hypotheses_never_become_observations(self):
        """Evidence with finding_classification INFERENCE or HYPOTHESIS is preserved as such."""
        rec_inf = self.adapter.adapt_generic_tool_output(
            tool_name="deductive_engine",
            tool_result={
                "finding": "Inferred memory leak from cumulative allocation trend",
                "finding_classification": "INFERENCE",
            },
            target_identity=self.target,
            session_id=self.session_id,
            evidence_id="ev_inf_test",
        )
        self.assertEqual(rec_inf.nature, NATURE_INFERENCE)

        rec_hyp = self.adapter.adapt_generic_tool_output(
            tool_name="deductive_engine",
            tool_result={
                "finding": "Hypothesized deadlock condition",
                "finding_classification": "HYPOTHESIS",
            },
            target_identity=self.target,
            session_id=self.session_id,
            evidence_id="ev_hyp_test",
        )
        self.assertEqual(rec_hyp.nature, NATURE_HYPOTHESIS)

    def test_16_parent_evidence_ids_preserved(self):
        """parent_evidence_ids are preserved on EvidenceRecord and survives ledger ingestion."""
        rec = self.adapter.adapt_generic_tool_output(
            tool_name="root_cause_tracker",
            tool_result={
                "finding": "Secondary corruption derived from chunk header overwrite",
                "parent_evidence_ids": ["ev_parent_01", "ev_parent_02"],
            },
            target_identity=self.target,
            session_id=self.session_id,
            evidence_id="ev_child_01",
        )
        self.assertEqual(rec.parent_evidence_ids, ["ev_parent_01", "ev_parent_02"])
        self.assertEqual(rec.details["parent_evidence_ids"], ["ev_parent_01", "ev_parent_02"])

    def test_17_partial_failed_and_budget_rejected_status_preserved(self):
        """Failed, partial, and budget-rejected observations retain their actual failure status."""
        rec_fail = self.adapter.adapt_generic_tool_output(
            tool_name="memory_reader",
            tool_result={"status": "FAILED", "error": "EPERM read error"},
            target_identity=self.target,
            session_id=self.session_id,
            evidence_id="ev_fail_test",
        )
        self.assertEqual(rec_fail.details["collection_status"], "ABSTAIN")
        self.assertEqual(rec_fail.details["result_category"], "OBSERVATION_FAILED")

        rec_partial = self.adapter.adapt_generic_tool_output(
            tool_name="memory_reader",
            tool_result={"status": "PARTIAL", "partial": True, "read_bytes": 8},
            target_identity=self.target,
            session_id=self.session_id,
            evidence_id="ev_partial_test",
        )
        self.assertEqual(rec_partial.details["collection_status"], "PARTIAL")
        self.assertEqual(rec_partial.details["result_category"], "PARTIAL_EVIDENCE")

    def test_18_end_to_end_investigation_step_acquires_genuine_live_receipt(self):
        """Full end-to-end investigation step against a live companion process acquires authentic receipt."""
        engine = ExpertDiagnosticEngine(corpus_dir="/tmp/p1_1_test_corpus")
        session = engine.start_investigation(
            problem_statement="0x7fff0038 주소 메모리 오염 의심",
            pid=self.pid,
            companion_elf=self.companion_elf,
        )
        # Advance through classify, assess, plan
        session.step()  # Classify -> Assessing
        session.step()  # Assess -> Planning
        session.step()  # Plan -> Collecting

        # Execute collecting step
        step_res = session.step()
        self.assertEqual(step_res["action"], "COLLECT_STEP")

        # Verify evidence in session.ledger
        records = session.ledger.get_records()
        self.assertGreater(len(records), 0)
        first_rec = records[0]
        self.assertIsNotNone(first_rec.evidence_id)
        # Because real memory was read from target process, genuine receipt was issued
        self.assertEqual(first_rec.provenance_class, PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE)
        self.assertIn("live_capture_receipt", first_rec.provenance)
        rcpt_dict = first_rec.provenance["live_capture_receipt"]
        self.assertEqual(rcpt_dict["pid"], self.pid)
        self.assertEqual(rcpt_dict["session_id"], session.ledger.session_id)


if __name__ == "__main__":
    unittest.main()
