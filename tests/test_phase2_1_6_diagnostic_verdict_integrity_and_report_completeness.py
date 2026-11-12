"""Phase 2.1.6 Validation Test Suite
Diagnostic Verdict Integrity & Report Completeness Closure (Tests A through T).

Verification Cases:
A. Two descriptive observations without Evidence IDs cannot produce CONFIRMED.
B. One unverified Evidence ID cannot produce CONFIRMED.
C. A nonexistent Evidence ID is rejected.
D. Evidence from another investigation or target is rejected.
E. Two derived records sharing one root evidence source do not count as independent evidence.
F. Repeated evidence insertion does not increase confidence.
G. Authoritative contradictory evidence changes the verdict.
H. Missing evidence remains INCONCLUSIVE, not REFUTED or CONFIRMED.
I. COMPLETED plus inconclusive checks cannot produce HEALTHY.
J. COMPLETED plus unexecuted required checks cannot automatically produce HEALTHY.
K. A fully inspected, explicitly healthy scenario can produce HEALTHY.
L. Confirmed fault remains visible despite unrelated PASS checks.
M. Failed chmod causes persistence failure.
N. File fsync, replace, and directory fsync failures have correctly distinguished durability outcomes.
O. Recovery preserves methodology, checks, evidence relationships, and verdict semantics.
P. Every planned but unexecuted recipe is explicitly represented without being counted as PASS.
Q. Every executed check has traceable criteria, observations, and evidence.
R. JSON, Markdown, HTML, Web, and MCP report data remain semantically equivalent.
S. Unknown duration is not represented as zero duration.
T. HTML output safely escapes target-controlled content.
"""

import html
import json
import os
import subprocess
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

from extractor.competing_hypotheses import (
    CompetingHypothesis,
    CompetingHypothesisManager,
    VERDICT_CONFIRMED,
    VERDICT_LIKELY,
    VERDICT_SUPPORTED,
    VERDICT_OBSERVED,
    VERDICT_REFUTED,
    VERDICT_INCONCLUSIVE,
    VERDICT_NOT_APPLICABLE,
)
from extractor.diagnostic_methodology import (
    CheckStatus,
    DiagnosticCheck,
    DiagnosticMethodology,
    MethodologySelector,
)
from extractor.diagnostic_report import (
    DiagnosticReport,
    ExecutiveSummarySection,
    DetailedInspectionResultsSection,
    DiagnosticStrategySection,
    EvidenceAndProvenanceSection,
    EvidenceIndexEntry,
    FinalConclusionsSection,
    FindingsSection,
    FindingRecord,
    LimitationsSection,
    TargetContextSection,
    CompetingHypothesesSection,
    CLASSIFICATION_CONFIRMED_ROOT_CAUSE,
    CLASSIFICATION_PROBABLE_CAUSE,
)
from extractor.diagnostic_verdict_aggregator import (
    DiagnosticVerdictAggregator,
    AggregatedVerdict,
    VERDICT_CONFIRMED_FAULT,
    VERDICT_PROBABLE_FAULT,
    VERDICT_HEALTHY,
    VERDICT_INCONCLUSIVE as AGG_INCONCLUSIVE,
    VERDICT_ABORTED as AGG_ABORTED,
)
from extractor.evidence_ledger import EvidenceLedger, EvidenceRecord
from extractor.expert_diagnostic_engine import (
    AdaptiveInvestigationSession,
    ExpertDiagnosticEngine,
    InvestigationPersistenceError,
    DurableCommitOutcome,
    STATE_COMPLETED,
    STATE_INCONCLUSIVE,
    STATE_BLOCKED,
)
from scripts.mcp_server import (
    runtime_inspect_investigation,
    runtime_get_investigation_report,
)
import scripts.mcp_server as _mcp_server


class TestPhase216DiagnosticVerdictIntegrity(unittest.TestCase):
    """Regression test cases A through T for Phase 2.1.6."""

    def test_case_a_descriptive_observations_without_evidence_ids_cannot_confirm(self):
        """Case A: Two descriptive observations without Evidence IDs cannot produce CONFIRMED."""
        hyp = CompetingHypothesis(
            hypothesis_id="HYP_A",
            category="MEMORY_LEAK",
            title="Unmanaged Memory Leak",
            confidence=0.95,
        )
        hyp.add_supporting_observation("Observed steady memory growth across intervals")
        hyp.add_supporting_observation("Observed zero garbage collection invocations")

        verdict = hyp.evaluate_verdict()
        self.assertNotEqual(verdict, VERDICT_CONFIRMED)
        self.assertIn(verdict, (VERDICT_LIKELY, VERDICT_SUPPORTED))
        self.assertEqual(len(hyp.supporting_evidence_ids), 0)

    def test_case_b_unverified_evidence_id_cannot_confirm(self):
        """Case B: One unverified Evidence ID cannot produce CONFIRMED."""
        hyp = CompetingHypothesis(
            hypothesis_id="HYP_B",
            category="MEMORY_CORRUPTION",
            title="Use-After-Free",
            confidence=0.98,
        )
        hyp.add_supporting_observation(
            "Target pointer references released chunk",
            evidence_id="EV_UNVERIFIED_99",
            is_verified=False,
        )
        verdict = hyp.evaluate_verdict()
        self.assertNotEqual(verdict, VERDICT_CONFIRMED)
        self.assertIn("EV_UNVERIFIED_99", hyp.unverified_evidence_ids)

    def test_case_c_nonexistent_evidence_id_rejected(self):
        """Case C: A nonexistent Evidence ID is rejected."""
        ledger = EvidenceLedger(session_id="INV_001")
        # Record only EV_001
        ledger.record(source="heap_inspector", observation="Chunk corrupted")
        existing_ev_id = ledger.records[0].evidence_id

        hyp = CompetingHypothesis(
            hypothesis_id="HYP_C",
            category="MEMORY_CORRUPTION",
            title="Heap Metadata Corruption",
        )
        # Adding a nonexistent evidence ID with ledger context
        added = hyp.add_supporting_observation(
            "Fake observation",
            evidence_id="EV_NONEXISTENT_999",
            target_context={"ledger": ledger},
        )
        self.assertFalse(added)
        self.assertNotIn("EV_NONEXISTENT_999", hyp.supporting_evidence_ids)

        # Adding valid existing ID
        added_valid = hyp.add_supporting_observation(
            "Valid observation",
            evidence_id=existing_ev_id,
            target_context={"ledger": ledger},
        )
        self.assertTrue(added_valid)
        self.assertIn(existing_ev_id, hyp.supporting_evidence_ids)

    def test_case_d_evidence_from_another_investigation_or_target_rejected(self):
        """Case D: Evidence from another investigation or target is rejected."""
        hyp = CompetingHypothesis(
            hypothesis_id="HYP_D",
            category="CONCURRENCY",
            title="Deadlock Inversion",
            investigation_id="INV_CORRECT_100",
            target_pid=5000,
            target_identity="host-embedded-1",
        )

        foreign_record = EvidenceRecord(
            evidence_id="EV_FOREIGN_01",
            session_id="INV_OTHER_999",  # Foreign investigation
            observation="Lock inversion observed on remote system",
        )

        added = hyp.add_supporting_observation(
            "Foreign lock wait",
            evidence_id="EV_FOREIGN_01",
            evidence_record=foreign_record,
            target_context={"investigation_id": "INV_CORRECT_100", "target_pid": 5000},
        )
        self.assertFalse(added)
        self.assertNotIn("EV_FOREIGN_01", hyp.supporting_evidence_ids)

    def test_case_e_two_derived_records_sharing_one_root_do_not_count_as_independent(self):
        """Case E: Two derived records sharing one root evidence source do not count as independent evidence."""
        from extractor.capture_backend import get_trusted_capture_authority_token, issue_live_capture_receipt
        from extractor.evidence_ledger import PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE
        ledger = EvidenceLedger(session_id="INV_T6_E")
        token = get_trusted_capture_authority_token()
        for eid in ["EV_ROOT_01", "EV_DERIVED_01", "EV_DERIVED_02", "EV_INDEPENDENT_ROOT_02"]:
            rcpt = issue_live_capture_receipt(
                session_id=ledger.session_id,
                pid=1234,
                process_identity="proc_1234",
                executable_identity="/proc/1234/exe",
                build_id="sha1:testbuildid12345",
                snapshot_binding="snap_1",
                capture_authority_token=token,
            )
            rec = EvidenceRecord(
                evidence_id=eid,
                session_id=ledger.session_id,
                evidence_type="DIAGNOSTIC",
                nature="observation",
                provenance={"provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE, "live_capture_receipt": rcpt.to_dict()},
                details={"provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE, "live_capture_receipt": rcpt.to_dict(), "target_pid": 1234},
                target_identity={"pid": 1234, "process_identity": "proc_1234", "executable_identity": "/proc/1234/exe", "build_id": "sha1:testbuildid12345"},
                observation=f"Observation for {eid}",
            )
            ledger._by_id[eid] = rec
            ledger._records.append(rec)
        hyp = CompetingHypothesis(
            hypothesis_id="HYP_E",
            category="MEMORY_LEAK",
            title="Monotonic Growth",
            confidence=0.95,
            ledger=ledger,
        )

        # Root evidence record
        hyp.add_supporting_observation("Root heap sample delta", evidence_id="EV_ROOT_01")

        # Derived record 1 and 2, both depending on EV_ROOT_01
        hyp.add_supporting_observation(
            "Derived allocation site rate",
            evidence_id="EV_DERIVED_01",
            depends_on=["EV_ROOT_01"],
        )
        hyp.add_supporting_observation(
            "Derived container retention count",
            evidence_id="EV_DERIVED_02",
            depends_on=["EV_ROOT_01"],
        )

        roots = hyp.get_independent_root_sources()
        # Even though 3 records exist, they all trace back to EV_ROOT_01!
        self.assertEqual(len(roots), 1)
        self.assertIn("EV_ROOT_01", roots)

        # Without an explicit primary single-evidence rule, 1 independent root cannot confirm!
        verdict = hyp.evaluate_verdict()
        self.assertEqual(verdict, VERDICT_LIKELY)
        self.assertNotEqual(verdict, VERDICT_CONFIRMED)

        # Adding a second distinct root evidence source
        hyp.add_supporting_observation(
            "Independent OS procfs VmRSS growth sample",
            evidence_id="EV_INDEPENDENT_ROOT_02",
        )
        roots2 = hyp.get_independent_root_sources()
        self.assertEqual(len(roots2), 2)
        verdict2 = hyp.evaluate_verdict()
        self.assertEqual(verdict2, VERDICT_CONFIRMED)

    def test_case_f_repeated_evidence_insertion_does_not_increase_confidence(self):
        """Case F: Repeated evidence insertion does not increase confidence."""
        hyp = CompetingHypothesis(
            hypothesis_id="HYP_F",
            category="MEMORY_LEAK",
            title="Heap Leak",
            confidence=0.50,
        )
        added1 = hyp.add_supporting_observation("Slope > 0", weight=0.20, evidence_id="EV_REP_01")
        self.assertTrue(added1)
        conf1 = hyp.confidence
        self.assertAlmostEqual(conf1, 0.70)

        # Repeat insertion of same evidence ID and observation
        added2 = hyp.add_supporting_observation("Slope > 0", weight=0.20, evidence_id="EV_REP_01")
        self.assertFalse(added2)
        conf2 = hyp.confidence
        self.assertEqual(conf1, conf2)  # Confidence unchanged

    def test_case_g_authoritative_contradictory_evidence_changes_verdict(self):
        """Case G: Authoritative contradictory evidence changes the verdict."""
        from extractor.capture_backend import get_trusted_capture_authority_token, issue_live_capture_receipt
        from extractor.evidence_ledger import PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE
        ledger = EvidenceLedger(session_id="INV_T6_G")
        token = get_trusted_capture_authority_token()
        for eid, obs_txt in [
            ("EV_UAF_1", "Wild access to 0x55550000"),
            ("EV_UAF_2", "Stack variable lifetime expired"),
            ("EV_STATIC_OK", "Address resides in valid global data segment with static lifetime"),
        ]:
            rcpt = issue_live_capture_receipt(
                session_id=ledger.session_id,
                pid=1234,
                process_identity="proc_1234",
                executable_identity="/proc/1234/exe",
                build_id="sha1:testbuildid12345",
                snapshot_binding="snap_1",
                capture_authority_token=token,
            )
            rec = EvidenceRecord(
                evidence_id=eid,
                session_id=ledger.session_id,
                evidence_type="DIAGNOSTIC",
                nature="observation",
                provenance={"provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE, "live_capture_receipt": rcpt.to_dict()},
                details={"provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE, "live_capture_receipt": rcpt.to_dict(), "target_pid": 1234},
                target_identity={"pid": 1234, "process_identity": "proc_1234", "executable_identity": "/proc/1234/exe", "build_id": "sha1:testbuildid12345"},
                observation=obs_txt,
            )
            ledger._by_id[eid] = rec
            ledger._records.append(rec)
        hyp = CompetingHypothesis(
            hypothesis_id="HYP_G",
            category="USE_AFTER_FREE",
            title="Use After Free",
            confidence=0.92,
            ledger=ledger,
        )
        hyp.add_supporting_observation("Wild access to 0x55550000", evidence_id="EV_UAF_1")
        hyp.add_supporting_observation("Stack variable lifetime expired", evidence_id="EV_UAF_2")
        self.assertEqual(hyp.evaluate_verdict(), VERDICT_CONFIRMED)

        # Add authoritative contradiction: address is an active global symbol
        hyp.add_contradicting_observation(
            "Address resides in valid global data segment with static lifetime",
            evidence_id="EV_STATIC_OK",
        )
        self.assertEqual(hyp.status, VERDICT_REFUTED)
        self.assertLessEqual(hyp.confidence, 0.15)

    def test_case_h_missing_evidence_remains_inconclusive(self):
        """Case H: Missing evidence remains INCONCLUSIVE, not REFUTED or CONFIRMED."""
        hyp = CompetingHypothesis(
            hypothesis_id="HYP_H",
            category="CONCURRENCY",
            title="Deadlock",
            confidence=0.95,
        )
        hyp.add_supporting_observation("Thread 1 blocked on mutex M1", evidence_id="EV_M1")
        hyp.missing_evidence.append("mutex_owner_thread_for_M1")

        verdict = hyp.evaluate_verdict()
        self.assertEqual(verdict, VERDICT_INCONCLUSIVE)
        self.assertNotEqual(verdict, VERDICT_CONFIRMED)
        self.assertNotEqual(verdict, VERDICT_REFUTED)

    def test_case_i_completed_plus_inconclusive_checks_cannot_produce_healthy(self):
        """Case I: COMPLETED plus inconclusive checks cannot produce HEALTHY."""
        checks = [
            DiagnosticCheck(
                check_id="CHK_01",
                description="Memory bounds check",
                status=CheckStatus.PASS,
            ),
            DiagnosticCheck(
                check_id="CHK_02",
                description="Freelist canary check",
                status=CheckStatus.INCONCLUSIVE,  # Inconclusive check!
            ),
        ]
        verdict = DiagnosticVerdictAggregator.aggregate(
            lifecycle_state="COMPLETED",
            stop_reason="ALL_HYPOTHESES_REFUTED",
            checks=checks,
            active_hypotheses=[],
        )
        self.assertNotEqual(verdict.overall_result, VERDICT_HEALTHY)
        self.assertEqual(verdict.overall_result, AGG_INCONCLUSIVE)
        self.assertTrue(any("INCONCLUSIVE" in f for f in verdict.limiting_factors))

    def test_case_j_completed_plus_unexecuted_required_checks_cannot_produce_healthy(self):
        """Case J: COMPLETED plus unexecuted required checks cannot automatically produce HEALTHY."""
        checks = [
            DiagnosticCheck(
                check_id="CHK_01",
                description="Heap layout check",
                status=CheckStatus.PASS,
            ),
            DiagnosticCheck(
                check_id="CHK_02",
                description="Lock graph cycle check",
                status=CheckStatus.NOT_EXECUTED,  # Planned check not executed!
            ),
        ]
        verdict = DiagnosticVerdictAggregator.aggregate(
            lifecycle_state="COMPLETED",
            stop_reason="ALL_HYPOTHESES_REFUTED",
            checks=checks,
            active_hypotheses=[],
        )
        self.assertNotEqual(verdict.overall_result, VERDICT_HEALTHY)
        self.assertEqual(verdict.overall_result, AGG_INCONCLUSIVE)
        self.assertTrue(any("NOT_EXECUTED" in f for f in verdict.limiting_factors))

    def test_case_k_fully_inspected_explicitly_healthy_scenario_produces_healthy(self):
        """Case K: A fully inspected, explicitly healthy scenario can produce HEALTHY."""
        checks = [
            DiagnosticCheck(
                check_id="CHK_01",
                description="Heap bounds check",
                status=CheckStatus.PASS,
            ),
            DiagnosticCheck(
                check_id="CHK_02",
                description="Lock graph acyclicity check",
                status=CheckStatus.PASS,
            ),
        ]
        verdict = DiagnosticVerdictAggregator.aggregate(
            lifecycle_state="COMPLETED",
            stop_reason="ALL_HYPOTHESES_REFUTED",
            checks=checks,
            active_hypotheses=[],
            limitations=[],
        )
        self.assertEqual(verdict.overall_result, VERDICT_HEALTHY)
        self.assertIn("verified healthy", verdict.verdict_rationale.lower())

    def test_case_l_confirmed_fault_remains_visible_despite_unrelated_pass_checks(self):
        """Case L: Confirmed fault remains visible despite unrelated PASS checks."""
        checks = [
            DiagnosticCheck(check_id="CHK_PASS_01", description="CPU usage", status=CheckStatus.PASS),
            DiagnosticCheck(check_id="CHK_PASS_02", description="Network buffers", status=CheckStatus.PASS),
            DiagnosticCheck(check_id="CHK_FAIL_01", description="Chunk PrevInuse", status=CheckStatus.FAIL),
        ]
        hyp = CompetingHypothesis(
            hypothesis_id="HYP_CORRUPTION",
            category="MEMORY_CORRUPTION",
            title="Chunk Header Overwrite",
            status=VERDICT_CONFIRMED,
        )
        verdict = DiagnosticVerdictAggregator.aggregate(
            lifecycle_state="COMPLETED",
            stop_reason="HYPOTHESIS_CONFIRMED",
            checks=checks,
            active_hypotheses=[hyp],
        )
        self.assertEqual(verdict.overall_result, VERDICT_CONFIRMED_FAULT)
        self.assertIn("Chunk Header Overwrite", verdict.confirmed_problems)

    def test_case_m_failed_chmod_causes_persistence_failure(self):
        """Case M: Failed chmod causes persistence failure."""
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = ExpertDiagnosticEngine(corpus_dir=tmpdir)
            session = engine.start_investigation("Persistence chmod test", pid=1234)

            # Patch os.chmod to simulate DAC failure
            with patch.object(os, "chmod", side_effect=PermissionError("Operation not permitted")):
                with self.assertRaises(InvestigationPersistenceError) as ctx:
                    session._save_to_disk()
                self.assertEqual(ctx.exception.outcome, DurableCommitOutcome.NOT_COMMITTED)

    def test_case_n_directory_fsync_failure_produces_commit_unknown(self):
        """Case N: File fsync, replace, and directory fsync failures have correctly distinguished durability outcomes."""
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = ExpertDiagnosticEngine(corpus_dir=tmpdir)
            session = engine.start_investigation("Durable commit test", pid=1234)

            # 1. Failure prior to replace -> NOT_COMMITTED
            with patch.object(os, "fsync", side_effect=OSError("I/O error during file fsync")):
                with self.assertRaises(InvestigationPersistenceError) as ctx_pre:
                    session._save_to_disk()
                self.assertEqual(ctx_pre.exception.outcome, DurableCommitOutcome.NOT_COMMITTED)

            # 2. Failure during directory fsync (AFTER os.replace) -> COMMIT_UNKNOWN
            orig_fsync = os.fsync
            call_count = [0]

            def selective_fsync(fd):
                call_count[0] += 1
                if call_count[0] == 1:
                    # First fsync is the temp file before replace -> succeed
                    return orig_fsync(fd)
                # Second fsync is the parent directory after replace -> fail!
                raise OSError("Directory sync failure after commit")

            with patch.object(os, "fsync", side_effect=selective_fsync):
                with self.assertRaises(InvestigationPersistenceError) as ctx_post:
                    session._save_to_disk()
                self.assertEqual(ctx_post.exception.outcome, DurableCommitOutcome.COMMIT_UNKNOWN)

    def test_case_o_recovery_preserves_methodology_checks_evidence_and_verdicts(self):
        """Case O: Recovery preserves methodology, checks, evidence relationships, and verdict semantics."""
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = ExpertDiagnosticEngine(corpus_dir=tmpdir)
            session = engine.start_investigation("Recovery fidelity test", pid=2222)

            ev = session.ledger.record(
                source="memory_inspector",
                observation="Freelist corruption detected",
            )
            chk = DiagnosticCheck(
                check_id="CHK_REC_01",
                methodology_name=session.methodology.name if session.methodology else "METH_GENERAL",
                recipe_id="RECIPE_HEAP_METADATA_CORRUPTION",
                description="Verify freelist integrity",
                technical_rationale="Invariants",
                status=CheckStatus.PASS,
                supporting_evidence_ids=[ev.evidence_id],
            )
            session.checks.append(chk)
            session._save_to_disk()

            # Restore in new engine instance
            restored_engine = ExpertDiagnosticEngine(corpus_dir=tmpdir)
            restored_sess = restored_engine.get_session(session.investigation_id)

            self.assertIsNotNone(restored_sess)
            self.assertEqual(len(restored_sess.checks), 1)
            self.assertEqual(restored_sess.checks[0].check_id, "CHK_REC_01")
            self.assertEqual(restored_sess.checks[0].supporting_evidence_ids, [ev.evidence_id])
            self.assertEqual(len(restored_sess.ledger.records), 1)
            self.assertEqual(restored_sess.ledger.records[0].evidence_id, ev.evidence_id)

    def test_case_p_planned_unexecuted_recipe_explicitly_represented_not_pass(self):
        """Case P: Every planned but unexecuted recipe is explicitly represented without being counted as PASS."""
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = ExpertDiagnosticEngine(corpus_dir=tmpdir)
            session = engine.start_investigation("Unexecuted planned recipe test", pid=os.getpid())
            session.step()  # CREATED -> ASSESSING
            session.step()  # ASSESSING -> PLANNING
            session.step()  # PLANNING -> COLLECTING (generates plan steps)

            self.assertIsNotNone(session.plan)
            self.assertGreater(len(session.plan.steps), 0)

            report = session.build_diagnostic_report()
            sec_d = report.section_d_detailed_inspection_results
            self.assertIsNotNone(sec_d)
            # Planned steps not yet executed must be NOT_EXECUTED, never PASS
            self.assertGreaterEqual(sec_d.checks_not_executed, 1)
            self.assertFalse(any(c["status"] == CheckStatus.PASS for c in sec_d.checks if "UNEXEC" in c["check_id"]))
            # Not executed checks must have duration_seconds as None (not 0.0)
            unexec_checks = [c for c in sec_d.checks if c["status"] == CheckStatus.NOT_EXECUTED]
            self.assertTrue(len(unexec_checks) > 0)
            self.assertIsNone(unexec_checks[0].get("duration_seconds"))

    def test_case_q_executed_checks_have_traceable_criteria_observations_evidence(self):
        """Case Q: Every executed check has traceable criteria, observations, and evidence."""
        chk = DiagnosticCheck(
            check_id="CHK_TRACE_01",
            methodology_name="Memory Integrity",
            recipe_id="RECIPE_USE_AFTER_FREE",
            description="Verify dangling pointer access",
            technical_rationale="POSIX mprotect guard",
            decision_criteria={"address_boundary": "> 0x1000"},
            inspected_entity="pointer_ptr1",
        )
        chk.start()
        chk.complete(
            status=CheckStatus.PASS,
            actual_observations={"address": "0x555555601000", "mapped": True},
            technical_interpretation="Pointer verified inside mapped heap region",
            supporting_evidence_ids=["EV_TRACE_01"],
        )
        d = chk.to_dict()
        self.assertIn("decision_criteria", d)
        self.assertIn("actual_observations", d)
        self.assertIn("supporting_evidence_ids", d)
        self.assertEqual(d["supporting_evidence_ids"], ["EV_TRACE_01"])
        self.assertIsNotNone(chk.duration_seconds)

    def test_case_r_single_source_report_consistency_json_markdown_html_mcp(self):
        """Case R: JSON, Markdown, HTML, Web, and MCP report data remain semantically equivalent."""
        # Resolve the MCP runtime at call time: other test modules replace scripts.mcp_server.runtime,
        # and a module-level import would bind a stale instance when the whole suite runs in one process.
        session = _mcp_server.runtime.expert_diagnostic_engine.start_investigation("Single source test", pid=4444)
        session.step()

        # 1. MCP JSON
        mcp_res_raw = runtime_get_investigation_report(session.investigation_id, format="json")
        mcp_data = json.loads(mcp_res_raw)
        self.assertTrue(mcp_data.get("success", False))
        mcp_rep = mcp_data["report"]

        # 2. Markdown
        md_raw = runtime_get_investigation_report(session.investigation_id, format="markdown")
        md_data = json.loads(md_raw)
        md_text = md_data["report"]

        # 3. HTML
        html_raw = runtime_get_investigation_report(session.investigation_id, format="html")
        html_data = json.loads(html_raw)
        html_text = html_data["report"]

        # Consistency checks
        self.assertEqual(mcp_rep["investigation_id"], session.investigation_id)
        self.assertIn(session.investigation_id, md_text)
        self.assertIn(session.investigation_id, html_text)
        self.assertIn(mcp_rep["section_a_executive_summary"]["overall_result"], md_text)
        self.assertIn(mcp_rep["section_a_executive_summary"]["overall_result"], html_text)

    def test_case_s_unknown_duration_not_represented_as_zero_duration(self):
        """Case S: Unknown duration is not represented as zero duration."""
        chk = DiagnosticCheck(
            check_id="CHK_UNEXEC",
            description="Unexecuted check",
            status=CheckStatus.NOT_EXECUTED,
            duration_seconds=None,
        )
        self.assertIsNone(chk.duration_seconds)
        self.assertIsNone(chk.duration_ms)

        report = DiagnosticReport(
            report_id="REP_DUR",
            investigation_id="INV_DUR",
            section_d_detailed_inspection_results=DetailedInspectionResultsSection(
                checks_total=1,
                checks_passed=0,
                checks_failed=0,
                checks_inconclusive=0,
                checks_not_applicable=0,
                checks_not_executed=1,
                checks_error=0,
                checks=[chk.to_dict()],
            ),
        )
        md_out = report.to_markdown()
        # Must NOT format as 0.0000s!
        self.assertNotIn("- **Duration**: `0.0000s`", md_out)
        self.assertIn("UNKNOWN", md_out)

        html_out = report.to_html()
        self.assertIn("UNKNOWN", html_out)

    def test_case_t_html_output_safely_escapes_target_controlled_content(self):
        """Case T: HTML output safely escapes target-controlled content."""
        malicious_input = '<script>alert("XSS")</script>'
        report = DiagnosticReport(
            report_id="REP_XSS",
            investigation_id="INV_XSS",
            section_a_executive_summary=ExecutiveSummarySection(
                target_identity=malicious_input,
                investigation_id="INV_XSS",
                overall_result="INCONCLUSIVE",
                confirmed_problems=[f"Corrupted buffer: {malicious_input}"],
                verdict_rationale=f"Observed malicious {malicious_input}",
            ),
            section_b_target_context=TargetContextSection(
                target_process_name=f"worker_{malicious_input}",
                pid=9999,
            ),
            section_d_detailed_inspection_results=DetailedInspectionResultsSection(
                checks_total=1,
                checks_passed=0,
                checks_failed=1,
                checks_inconclusive=0,
                checks_not_applicable=0,
                checks_not_executed=0,
                checks_error=0,
                checks=[
                    DiagnosticCheck(
                        check_id="CHK_XSS",
                        description=f"Inspect {malicious_input}",
                        technical_rationale=malicious_input,
                        actual_observations={"payload": malicious_input},
                        status=CheckStatus.FAIL,
                    ).to_dict()
                ],
            ),
        )
        html_out = report.to_html()
        # Raw unescaped script tag must NOT be present
        self.assertNotIn('<script>alert("XSS")</script>', html_out)
        # Escaped entity must be present
        self.assertIn('&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;', html_out)


if __name__ == "__main__":
    unittest.main()
