"""Phase 1 — Canonical Evidence Ingestion & Trust Boundary Integration Test Suite.

Verifies:
- Group A: Normal ingestion flow through EvidenceAdapter and EvidenceLedger.
- Group B: Provenance and trust preservation (live vs synthetic vs imported, receipts, PID/session matching).
- Group C: Evidence relationships, DAG parents, hypothesis links, and semantic deduplication.
- Group D: Failure behavior, fail-closed validation, conflict resolution, invalid inputs.
- Group E: MCP entry points and end-to-end regression across investigation lifecycle.
"""

import json
import os
import subprocess
import time
import unittest

from tests.fixture_builds import ensure_expert_diagnostic_fixture
from extractor.capture_backend import (
    LiveCaptureReceipt,
    get_trusted_capture_authority_token,
    issue_live_capture_receipt,
)
from extractor.evidence_adapter import (
    EvidenceAdapter,
    PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
    PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
    PROVENANCE_CLASS_SYNTHETIC_FIXTURE,
)
from extractor.evidence_ledger import (
    EvidenceLedger,
    EvidenceRecord,
    EVIDENCE_TYPE_DIAGNOSTIC,
    NATURE_OBSERVATION,
)
from extractor.expert_diagnostic_engine import (
    AdaptiveInvestigationSession,
    ExpertDiagnosticEngine,
)
from extractor.agent_runtime import AgentRuntime
import scripts.mcp_server as mcp_srv


class TestPhase1CanonicalEvidenceIngestion(unittest.TestCase):
    """Test suite for Phase 1 canonical evidence ingestion and trust boundaries."""

    def setUp(self):
        self.session_id = "sess_p1_test_001"
        self.ledger = EvidenceLedger(session_id=self.session_id)
        self.adapter = EvidenceAdapter()
        self.target_pid = os.getpid()
        self.proc_ident = f"proc_{self.target_pid}_test"
        self.exe_ident = f"/proc/{self.target_pid}/exe"
        self.build_id = "sha1:build_phase1_abc123"
        self.target = {
            "pid": self.target_pid,
            "process_identity": self.proc_ident,
            "executable_identity": self.exe_ident,
            "build_id": self.build_id,
            "session_id": self.session_id,
        }

    # =========================================================================
    # Group A: Normal Ingestion Flow
    # =========================================================================

    def test_group_a_adapt_generic_tool_output_and_ledger_registration(self):
        """Verifies raw observation normalization, adapter output, and ledger registration."""
        raw_output = {
            "address": "0x7fff12340000",
            "status": "CORRUPTED",
            "details": "Chunk header overwritten by 0xdeadbeef",
            "evidence_id": "evi_chunk_corrupt_01",
        }
        rec = self.adapter.adapt_generic_tool_output(
            tool_name="memory_inspector",
            tool_result=raw_output,
            target_identity=self.target,
            session_id=self.session_id,
            evidence_id="evi_chunk_corrupt_01",
        )
        self.assertIsNotNone(rec)
        self.assertEqual(rec.evidence_id, "evi_chunk_corrupt_01")
        self.assertEqual(rec.target_pid, self.target_pid)
        self.assertEqual(rec.nature, NATURE_OBSERVATION)
        self.assertIn("semantic_digest", rec.details)

        # Register in ledger
        rec_list = self.adapter.record_into_ledger(rec, self.ledger, raise_on_error=True)
        self.assertEqual(len(rec_list), 1)
        self.assertEqual(rec_list[0].evidence_id, "evi_chunk_corrupt_01")

        # Retrieve and verify canonical record
        retrieved = self.ledger.get_record("evi_chunk_corrupt_01")
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.evidence_id, "evi_chunk_corrupt_01")
        self.assertEqual(retrieved.target_pid, self.target_pid)
        self.assertEqual(retrieved.provenance_class, PROVENANCE_CLASS_IMPORTED_UNVERIFIED)

    def test_group_a_expert_engine_session_records_via_adapter_no_private_mutation(self):
        """Verifies AdaptiveInvestigationSession routes evidence through adapter and does NOT touch private collections directly."""
        engine = ExpertDiagnosticEngine(corpus_dir="/tmp/phase1_test_corpus")
        session = engine.start_investigation(
            problem_statement="0x7fff0038 주소에서 세그폴트 및 메모리 오염 의심",
            pid=self.target_pid,
            companion_elf=ensure_expert_diagnostic_fixture(need_stripped=False)[0],
        )

        # Check adapter is initialized on session
        self.assertTrue(hasattr(session, "evidence_adapter"))
        self.assertIsInstance(session.evidence_adapter, EvidenceAdapter)

        # Record evidence via session method
        status = session._record_authoritative_evidence_in_ledger(
            ev_id="ev_step_norm_01",
            recipe_id="RECIPE_MEM_01",
            observation_text="Address 0xdeadbeef is outside mapped heap",
            prov_class=PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
            enriched_ev={
                "finding": "Out of bounds pointer dereference",
                "finding_classification": "INVALID_ADDRESS",
                "step_id": "step_check_bounds",
                "raw_observation": {"address": "0xdeadbeef", "size": 64},
                "normalized_observation": "Address 0xdeadbeef is outside mapped heap",
                "target_pid": self.target_pid,
                "source_correlation": {"file": "main.cpp", "line": 42},
            },
        )
        self.assertEqual(status, "RECORDED")

        # Verify evidence in session.ledger
        rec = session.ledger.get_record("ev_step_norm_01")
        self.assertIsNotNone(rec)
        self.assertEqual(rec.evidence_id, "ev_step_norm_01")
        self.assertEqual(rec.details["recipe_id"], "RECIPE_MEM_01")
        self.assertEqual(rec.details["step_id"], "step_check_bounds")
        self.assertEqual(rec.details["finding"], "Out of bounds pointer dereference")
        self.assertEqual(rec.details["finding_classification"], "INVALID_ADDRESS")
        self.assertEqual(rec.target_pid, self.target_pid)

    # =========================================================================
    # Group B: Trust Boundary & Provenance Validation
    # =========================================================================

    def test_group_b_live_capture_receipt_valid_provenance(self):
        """Verifies genuine LiveCaptureReceipt receives PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE and passes ledger validation."""
        auth_token = get_trusted_capture_authority_token()
        receipt = issue_live_capture_receipt(
            session_id=self.session_id,
            pid=self.target_pid,
            process_identity=self.proc_ident,
            executable_identity=self.exe_ident,
            build_id=self.build_id,
            snapshot_binding="snap_p1_001",
            capture_authority_token=auth_token,
        )
        self.assertIsNotNone(receipt)

        rec = self.adapter.adapt_generic_tool_output(
            tool_name="live_memory_sampler",
            tool_result={"raw_val": 0x41414141, "live_capture_receipt": receipt.to_dict()},
            target_identity=self.target,
            session_id=self.session_id,
            evidence_id="evi_live_valid_01",
        )
        self.assertEqual(rec.provenance_class, PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE)
        self.assertIn("live_capture_receipt", rec.provenance)
        self.assertIn("live_capture_receipt", rec.details)

        # Ingestion into ledger must succeed
        reg_list = self.adapter.record_into_ledger(rec, self.ledger, raise_on_error=True)
        self.assertEqual(len(reg_list), 1)
        self.assertEqual(reg_list[0].evidence_id, "evi_live_valid_01")
        ledger_rec = self.ledger.get_record("evi_live_valid_01")
        self.assertEqual(ledger_rec.provenance_class, PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE)

    def test_group_b_synthetic_fixture_cannot_escalate_to_live(self):
        """Verifies synthetic test fixtures cannot claim live capture or be escalated."""
        rec = self.adapter.adapt_generic_tool_output(
            tool_name="mock_fixture_tool",
            tool_result={"mock_flag": True, "fixture_name": "double_free_mock", "is_synthetic": True},
            target_identity=self.target,
            session_id=self.session_id,
            evidence_id="evi_synthetic_01",
        )
        self.assertEqual(rec.provenance_class, PROVENANCE_CLASS_SYNTHETIC_FIXTURE)
        self.assertNotIn("live_capture_receipt", rec.provenance)

        reg_list = self.adapter.record_into_ledger(rec, self.ledger, raise_on_error=True)
        self.assertEqual(len(reg_list), 1)
        self.assertEqual(reg_list[0].evidence_id, "evi_synthetic_01")

    def test_group_b_forged_live_provenance_rejected(self):
        """Verifies that claiming LIVE_RUNTIME_CAPTURE without valid LiveCaptureReceipt is rejected fail-closed."""
        forged_rec = EvidenceRecord(
            evidence_id="evi_forged_01",
            evidence_type=EVIDENCE_TYPE_DIAGNOSTIC,
            nature=NATURE_OBSERVATION,
            provenance={"provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE},
            details={"provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE},
            source="untrusted_source",
            session_id=self.session_id,
            target_identity=self.target,
        )
        with self.assertRaises(ValueError):
            self.ledger.add_record(forged_rec)

    def test_group_b_receipt_pid_mismatch_rejected(self):
        """Verifies receipt with mismatched PID is rejected."""
        auth_token = get_trusted_capture_authority_token()
        mismatched_pid = self.target_pid + 9999
        receipt = issue_live_capture_receipt(
            session_id=self.session_id,
            pid=mismatched_pid,
            process_identity=self.proc_ident,
            executable_identity=self.exe_ident,
            build_id=self.build_id,
            snapshot_binding="snap_p1_001",
            capture_authority_token=auth_token,
        )
        rec = EvidenceRecord(
            evidence_id="evi_mismatched_pid",
            evidence_type=EVIDENCE_TYPE_DIAGNOSTIC,
            nature=NATURE_OBSERVATION,
            provenance={
                "provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
                "live_capture_receipt": receipt.to_dict(),
            },
            details={
                "provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
                "live_capture_receipt": receipt.to_dict(),
                "target_pid": self.target_pid,
            },
            source="proc_mem",
            session_id=self.session_id,
            target_identity=self.target,
        )
        with self.assertRaises(ValueError):
            self.ledger.add_record(rec)

    # =========================================================================
    # Group C: Evidence Relationships & Graph DAG
    # =========================================================================

    def test_group_c_parent_causality_and_duplicate_deduplication(self):
        """Verifies parent evidence tracking and semantic deduplication."""
        rec1 = self.adapter.adapt_generic_tool_output(
            tool_name="leak_detector",
            tool_result={"unfreed_bytes": 1024, "alloc_site": "parser.cpp:15"},
            target_identity=self.target,
            session_id=self.session_id,
            evidence_id="evi_leak_parent",
        )
        self.ledger.add_record(rec1)

        # Child evidence referencing rec1
        rec2 = self.adapter.adapt_generic_tool_output(
            tool_name="heap_walker",
            tool_result={"referenced_chunk": "0x5555557788", "retained_by": "evi_leak_parent"},
            target_identity=self.target,
            session_id=self.session_id,
            evidence_id="evi_leak_child",
        )
        rec2.parent_evidence_ids = ["evi_leak_parent"]
        self.ledger.add_record(rec2)

        retrieved_child = self.ledger.get_record("evi_leak_child")
        self.assertIn("evi_leak_parent", retrieved_child.parent_evidence_ids)

        # Semantic deduplication through session._record_authoritative_evidence_in_ledger
        engine = ExpertDiagnosticEngine(corpus_dir="/tmp/phase1_test_corpus")
        session = engine.start_investigation(
            problem_statement="메모리 누수 의심",
            pid=self.target_pid,
        )
        st1 = session._record_authoritative_evidence_in_ledger(
            ev_id="ev_leak_01",
            recipe_id="RECIPE_LEAK",
            observation_text="Leak detected: 1024 bytes",
            prov_class=PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
            enriched_ev={
                "finding": "Leak 1024 bytes",
                "finding_classification": "LEAK",
                "step_id": "step1",
                "raw_observation": {"bytes": 1024},
                "normalized_observation": "Leak detected: 1024 bytes",
            },
        )
        self.assertEqual(st1, "RECORDED")

        # Second record with different ID but same exact content
        st2 = session._record_authoritative_evidence_in_ledger(
            ev_id="ev_leak_02",
            recipe_id="RECIPE_LEAK",
            observation_text="Leak detected: 1024 bytes",
            prov_class=PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
            enriched_ev={
                "finding": "Leak 1024 bytes",
                "finding_classification": "LEAK",
                "step_id": "step1",
                "raw_observation": {"bytes": 1024},
                "normalized_observation": "Leak detected: 1024 bytes",
            },
        )
        self.assertTrue(st2.startswith("DUPLICATE:"))

    # =========================================================================
    # Group D: Failure & Error Handling
    # =========================================================================

    def test_group_d_duplicate_id_with_different_content_raises_conflict(self):
        """Verifies registering a distinct record with an already used evidence_id fails-closed."""
        rec1 = EvidenceRecord(
            evidence_id="evi_conflict_01",
            evidence_type=EVIDENCE_TYPE_DIAGNOSTIC,
            nature=NATURE_OBSERVATION,
            provenance={"provenance_class": PROVENANCE_CLASS_IMPORTED_UNVERIFIED},
            details={"payload_digest": "digest_a", "semantic_digest": "sem_a"},
            source="tool_a",
            observation="Obs A",
            session_id=self.session_id,
        )
        self.ledger.add_record(rec1)

        rec2 = EvidenceRecord(
            evidence_id="evi_conflict_01",  # Same ID!
            evidence_type=EVIDENCE_TYPE_DIAGNOSTIC,
            nature=NATURE_OBSERVATION,
            provenance={"provenance_class": PROVENANCE_CLASS_IMPORTED_UNVERIFIED},
            details={"payload_digest": "digest_b", "semantic_digest": "sem_b"},
            source="tool_b",
            observation="Obs B - Different!",
            session_id=self.session_id,
        )
        with self.assertRaises(ValueError):
            self.adapter.record_into_ledger(rec2, self.ledger, raise_on_error=True)

    def test_group_d_invalid_provenance_class_rejected(self):
        """Verifies unknown/invalid provenance class is rejected."""
        rec = EvidenceRecord(
            evidence_id="evi_bad_prov",
            evidence_type=EVIDENCE_TYPE_DIAGNOSTIC,
            nature=NATURE_OBSERVATION,
            provenance={"provenance_class": "UNKNOWN_PROVENANCE_LEVEL_99"},
            details={"provenance_class": "UNKNOWN_PROVENANCE_LEVEL_99"},
            source="tool",
            session_id=self.session_id,
        )
        with self.assertRaises(ValueError):
            self.ledger.add_record(rec)

    # =========================================================================
    # Group E: MCP Entry Points & End-to-End Regression
    # =========================================================================

    def test_group_e_mcp_lifecycle_and_canonical_evidence_flow(self):
        """Verifies MCP tools invoke canonical evidence ingestion and reports reflect valid evidence."""
        companion_elf, _ = ensure_expert_diagnostic_fixture(need_stripped=False)
        proc = subprocess.Popen([companion_elf, "healthy"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(0.15)
        pid = proc.pid

        try:
            runtime = AgentRuntime(corpus_dir="/tmp/phase1_mcp_test_corpus")
            mcp_srv.runtime = runtime

            # 1. Start investigation via MCP tool
            raw_start = mcp_srv.runtime_start_investigation(
                problem_statement="0x7fff0038 주소에서 세그폴트 발생",
                pid=pid,
                companion_elf=companion_elf,
            )
            res_start = json.loads(raw_start)
            self.assertTrue(res_start["success"])
            inv_id = res_start["data"]["investigation_id"]
            self.assertIsNotNone(inv_id)

            # 2. Inspect session
            session = runtime.expert_diagnostic_engine.get_session(inv_id)
            self.assertIsNotNone(session)
            self.assertTrue(hasattr(session, "evidence_adapter"))

            # 3. Execute planned step
            plan = session.plan
            self.assertIsNotNone(plan)
            self.assertGreater(len(plan.steps), 0)
            first_step = plan.steps[0]

            raw_step = mcp_srv.runtime_execute_investigation_step(
                investigation_id=inv_id,
                step_id=first_step.step_id,
            )
            res_step = json.loads(raw_step)
            self.assertTrue(res_step["success"])

            # Verify evidence recorded in session.ledger
            ledger_records = session.ledger.records
            self.assertGreater(len(ledger_records), 0)
            first_rec = ledger_records[0]
            self.assertIsNotNone(first_rec.evidence_id)
            self.assertIn("semantic_digest", first_rec.details)

            # 4. Export report via MCP tool
            raw_report = mcp_srv.runtime_export_incident_report(investigation_id=inv_id, format="json")
            report_res = json.loads(raw_report)
            self.assertTrue(report_res["success"])
            report_data = report_res["report"]
            self.assertIn("section_g_evidence_and_provenance", report_data)

            # 5. Session serialization and reconstruction preserves adapter and ledger
            s_dict = session.to_dict()
            restored_session = AdaptiveInvestigationSession.from_dict(s_dict)
            self.assertTrue(hasattr(restored_session, "evidence_adapter"))
            self.assertEqual(len(restored_session.ledger.records), len(session.ledger.records))

        finally:
            try:
                if proc.stdout:
                    proc.stdout.close()
                if proc.stderr:
                    proc.stderr.close()
                proc.terminate()
                proc.wait(timeout=1.0)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass


if __name__ == "__main__":
    unittest.main()
