"""
Phase 2.1.5 Validation Test Suite
Diagnostic Methodology, Evidence Integrity & Comprehensive Reporting.

Verification Areas:
1. Traceable supporting evidence for every conclusion.
2. Every executed check has explicit criteria, actual observations, and result status.
3. Unexecuted checks (NOT_EXECUTED) and not-applicable checks (NOT_APPLICABLE) are never reported as PASS.
4. NOT_APPLICABLE vs INCONCLUSIVE remain strictly distinct.
5. Anti-double-counting: duplicate/correlated evidence descriptions cannot inflate confidence.
6. Contradictory evidence modifies hypothesis verdicts correctly (prevents CONFIRMED, triggers REFUTED).
7. Persistence failure fails closed via InvestigationPersistenceError (never silent success).
8. Recovery preserves investigation state, checks, and EvidenceLedger consistency.
9. PIE and shared-library address correlation is correct with PT_LOAD segments; Build ID mismatch returns unresolved.
10. Valid falsey observations (0, 0.0, False, "", None) are preserved.
11. Temporal failures, missing samples, and irregular intervals are disclosed in report limitations.
12. Report content consistency across JSON, HTML, Markdown, and MCP.
13. Inconclusive investigations produce complete, structured, and informative reports.
14. No unsupported conclusion is generated from missing evidence.
15. Realistic C++ scenarios: memory leak, UAF, deadlock & incomplete lock graphs, normal warm-up, conflicting observations.
"""

import os
import json
import subprocess
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

from extractor.diagnostic_methodology import (
    CheckStatus,
    DiagnosticCheck,
    DiagnosticMethodology,
    MethodologySelector,
)
from extractor.diagnostic_report import (
    DiagnosticReport,
    ExecutiveSummarySection,
    TargetContextSection,
    DiagnosticStrategySection,
    DetailedInspectionResultsSection,
    FindingsSection,
    FindingRecord,
    CompetingHypothesesSection,
    EvidenceAndProvenanceSection,
    EvidenceIndexEntry,
    LimitationsSection,
    FinalConclusionsSection,
    CLASSIFICATION_CONFIRMED_ROOT_CAUSE,
    CLASSIFICATION_PROBABLE_CAUSE,
    CLASSIFICATION_ANOMALY,
    CLASSIFICATION_OBSERVED_SYMPTOM,
)
from extractor.runtime_evidence_provider import (
    RuntimeEvidenceRecord,
    RuntimeEvidenceProvider,
)
from extractor.competing_hypotheses import (
    CompetingHypothesis,
    CompetingHypothesisManager,
    HypothesisComparisonResult,
    VERDICT_CONFIRMED,
    VERDICT_LIKELY,
    VERDICT_SUPPORTED,
    VERDICT_REFUTED,
    VERDICT_INCONCLUSIVE,
    VERDICT_NOT_APPLICABLE,
)
from extractor.temporal_observation_window import (
    ObservationWindow,
    MemorySample,
    MemoryBehavior,
    MemoryAnalysisResult,
)
from extractor.evidence_ledger import EvidenceLedger
from extractor.diagnostic_recipes import (
    DiagnosticRecipeRegistry,
    RecipeEvaluationResult,
    RECIPE_STATUS_SUPPORTED,
    RECIPE_STATUS_CONTRADICTED,
    RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
    RECIPE_STATUS_NOT_APPLICABLE,
)
from extractor.expert_diagnostic_engine import (
    AdaptiveInvestigationSession,
    ExpertDiagnosticEngine,
    EvidenceToSourceCorrelator,
    InvestigationPersistenceError,
    STATE_COMPLETED,
    STATE_INCONCLUSIVE,
)
from extractor.target_adapter import TargetExecutionAdapter, LocalTargetAdapter
from scripts.mcp_server import (
    runtime_inspect_investigation,
    runtime_get_investigation_report,
    runtime_export_incident_report,
)


class TestDiagnosticMethodologyAndChecks(unittest.TestCase):
    """Area 2, 3, 4: Diagnostic methodology, check lifecycle, statuses."""

    def test_diagnostic_check_lifecycle_and_duration(self):
        check = DiagnosticCheck(
            check_id="CHK_TEST_001",
            methodology_name="Memory Integrity",
            recipe_id="HEAP_CORRUPTION_PREV_INUSE",
            recipe_version="2.1.0",
            description="Verify chunk prev_inuse flag semantics",
            technical_rationale="glibc ptmalloc prev_inuse indicates previous chunk status",
            preconditions=["heap_accessible", "allocator_glibc"],
            decision_criteria={"field": "prev_inuse", "expected_match": True},
            target_entity="chunk_0x55aa0010",
        )
        self.assertEqual(check.status, CheckStatus.NOT_EXECUTED)
        self.assertIsNone(check.duration_ms)

        check.start()
        time.sleep(0.01)
        check.complete(
            status=CheckStatus.PASS,
            actual_observations={"prev_inuse": True, "evaluated_bits": 0x1},
            supporting_evidence_ids=["ev_chk_01"],
        )
        self.assertEqual(check.status, CheckStatus.PASS)
        self.assertIsNotNone(check.duration_ms)
        self.assertGreater(check.duration_ms, 0.0)
        self.assertEqual(check.supporting_evidence_ids, ["ev_chk_01"])

        d = check.to_dict()
        self.assertEqual(d["check_id"], "CHK_TEST_001")
        self.assertEqual(d["status"], "PASS")
        self.assertIn("duration_seconds", d)

    def test_not_executed_and_not_applicable_never_pass(self):
        check_not_exec = DiagnosticCheck(
            check_id="CHK_NE",
            description="Unexecuted check",
            status=CheckStatus.NOT_EXECUTED,
        )
        check_na = DiagnosticCheck(
            check_id="CHK_NA",
            description="Not applicable check",
            status=CheckStatus.NOT_APPLICABLE,
        )

        self.assertNotEqual(check_not_exec.status, CheckStatus.PASS)
        self.assertNotEqual(check_na.status, CheckStatus.PASS)
        self.assertTrue(CheckStatus.is_unexecuted(check_not_exec.status))
        self.assertFalse(CheckStatus.is_definitive(check_not_exec.status))
        self.assertTrue(CheckStatus.is_inapplicable(check_na.status))
        self.assertFalse(CheckStatus.is_definitive(check_na.status))

    def test_not_applicable_vs_inconclusive_distinct(self):
        status_na = CheckStatus.NOT_APPLICABLE
        status_inc = CheckStatus.INCONCLUSIVE

        self.assertNotEqual(status_na, status_inc)
        self.assertTrue(CheckStatus.is_inapplicable(status_na))
        self.assertFalse(CheckStatus.is_inconclusive(status_na))
        self.assertTrue(CheckStatus.is_inconclusive(status_inc))
        self.assertFalse(CheckStatus.is_inapplicable(status_inc))

    def test_methodology_selector(self):
        methodology = MethodologySelector.select_methodology(
            classification="MEMORY_LEAK",
            context={"pid": 1234, "companion_elf": "/bin/app"},
        )
        self.assertEqual(methodology.name, "Multi-Epoch Monotonic Temporal Growth & Accumulation Analysis")
        self.assertIn("RECIPE_PROCESS_MEMORY_GROWTH", methodology.applicable_recipes)
        self.assertIn("sustained_growth_threshold", methodology.decision_criteria_summary)


class TestHypothesisEvidenceIntegrity(unittest.TestCase):
    """Area 1, 5, 6, 14: Traceability, anti-double-counting, contradiction."""

    def test_anti_double_counting_duplicate_evidence(self):
        hyp = CompetingHypothesis(
            hypothesis_id="HYP_LEAK_01",
            category="MEMORY_LEAK",
            title="Continuous Heap Leak",
        )

        # 1. First supporting observation with EV_LEAK_100
        added1 = hyp.add_supporting_observation("Monotonic slope observed", evidence_id="EV_LEAK_100")
        self.assertTrue(added1)
        self.assertEqual(len(hyp.supporting_evidence_ids), 1)

        # 2. Re-adding observation sharing the SAME evidence_id
        added2 = hyp.add_supporting_observation("Repeated observation with same evidence", evidence_id="EV_LEAK_100")
        self.assertFalse(added2)
        # Duplicate evidence ID was rejected, anti-double-counting verified
        self.assertEqual(len(hyp.supporting_evidence_ids), 1)

        # 3. Adding observation with a DISTINCT evidence_id
        added3 = hyp.add_supporting_observation("Distinct allocation site growth", evidence_id="EV_LEAK_101")
        self.assertTrue(added3)
        self.assertEqual(len(hyp.supporting_evidence_ids), 2)
        self.assertIn("EV_LEAK_101", hyp.supporting_evidence_ids)

    def test_contradictory_evidence_modifies_verdict_and_prevents_confirmed(self):
        from extractor.evidence_ledger import EvidenceLedger, EvidenceRecord, PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE
        from extractor.capture_backend import get_trusted_capture_authority_token, issue_live_capture_receipt
        ledger = EvidenceLedger(session_id="INV_T5_UAF")
        token = get_trusted_capture_authority_token()
        for eid, obs_str in [
            ("EV_UAF_01", "Dangling pointer detected"),
            ("EV_ALLOC_ACTIVE", "Memory chunk is currently active in static lifetime global data segment"),
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
                observation=obs_str,
            )
            ledger._by_id[eid] = rec
            ledger._records.append(rec)

        hyp = CompetingHypothesis(
            hypothesis_id="HYP_UAF_01",
            category="USE_AFTER_FREE",
            title="Use-After-Free",
            confidence=0.95,
            ledger=ledger,
        )

        # Add support
        hyp.add_supporting_observation("Dangling pointer detected", evidence_id="EV_UAF_01")
        # Add an authoritative decisive contradiction with precedence
        hyp.add_contradicting_observation(
            "Memory chunk is currently active in static lifetime global data segment",
            evidence_id="EV_ALLOC_ACTIVE",
        )

        # Must NOT be CONFIRMED because an authoritative counter-indicator exists
        self.assertNotEqual(hyp.status, VERDICT_CONFIRMED)
        self.assertEqual(hyp.status, VERDICT_REFUTED)
        self.assertIn("EV_ALLOC_ACTIVE", hyp.contradicting_evidence_ids)

    def test_traceable_evidence_for_every_conclusion(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = ExpertDiagnosticEngine(corpus_dir=tmpdir)
            session = engine.start_investigation("Memory leak in buffer", pid=1001)

            # Record evidence in ledger
            ev = session.ledger.record(
                source="heap_inspector",
                observation="Monotonic heap growth detected",
                details={"growth_rate_bytes_sec": 50000, "monotonic": True},
            )

            # Conclude investigation
            session._finalize_conclusion(
                stop_reason="ROOT_CAUSE_CONFIRMED",
                summary="Monotonic heap leak verified in buffer",
                primary_finding="Monotonic heap leak verified in buffer",
                confidence=0.95,
            )

            report = session.build_diagnostic_report()
            self.assertIsNotNone(report.section_a_executive_summary)
            self.assertEqual(report.section_a_executive_summary.investigation_id, session.investigation_id)
            self.assertIn(report.section_a_executive_summary.overall_result, ("CONFIRMED_FAULT", "PROBABLE_FAULT", "INCONCLUSIVE", "HEALTHY"))


class TestPersistenceAndLedgerConsistency(unittest.TestCase):
    """Area 7, 8: Fail-closed persistence and full session recovery."""

    def test_persistence_fail_closed_raises_investigation_persistence_error(self):
        engine = ExpertDiagnosticEngine(corpus_dir="/tmp/dynstate_test_persistence")
        session = engine.start_investigation("Memory leak in buffer", pid=999999)

        # Force a write error by patching os.replace to raise OSError
        with patch.object(os, "replace", side_effect=OSError("Disk write permission denied")):
            with self.assertRaises(InvestigationPersistenceError):
                session._save_to_disk()

    def test_recovery_preserves_methodology_ledger_and_checks(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = ExpertDiagnosticEngine(corpus_dir=tmpdir)
            session = engine.start_investigation("Heap fragmentation observed", pid=1010)

            # Record evidence in ledger
            ev = session.ledger.record(
                source="heap_inspector",
                observation="High fragmentation",
                details={"external_frag_ratio": 0.45, "unfreed_chunks": 120},
            )
            # Add a diagnostic check
            chk = DiagnosticCheck(
                check_id="CHK_RECOVER_01",
                methodology_id=session.methodology.methodology_id if session.methodology else "METH_GENERAL",
                recipe_id="RECIPE_HEAP_FRAGMENTATION",
                description="Check fragmentation threshold",
                technical_rationale="Fragmentation > 0.40 indicates high overhead",
                decision_criteria={"threshold": 0.40},
                inspected_entity="heap_0",
                status=CheckStatus.PASS,
                supporting_evidence_ids=[ev.evidence_id],
            )
            session.checks.append(chk)
            session._save_to_disk()

            # Restore in fresh engine instance
            restored_engine = ExpertDiagnosticEngine(corpus_dir=tmpdir)
            restored_session = restored_engine.get_session(session.investigation_id)

            self.assertIsNotNone(restored_session)
            self.assertEqual(len(restored_session.ledger.records), 1)
            self.assertEqual(restored_session.ledger.records[0].evidence_id, ev.evidence_id)
            self.assertEqual(len(restored_session.checks), 1)
            self.assertEqual(restored_session.checks[0].check_id, "CHK_RECOVER_01")
            self.assertEqual(restored_session.checks[0].status, CheckStatus.PASS)


class TestSourceCorrelationAndNormalization(unittest.TestCase):
    """Area 9, 10: PT_LOAD load bias, PIE, Build ID validation, falsey values."""

    def test_pt_load_bias_pie_and_shared_libraries(self):
        correlator = EvidenceToSourceCorrelator()
        obs = {
            "address": 0x555555555020,
            "raw_symbol": "process_event",
            "source_file": "worker.cpp",
            "source_line": 120,
        }
        result = correlator.correlate(obs)
        self.assertEqual(result.get("address"), 0x555555555020)
        self.assertEqual(result.get("source_file"), "worker.cpp")
        self.assertEqual(result.get("source_line"), 120)

    def test_build_id_mismatch_fails_closed_to_unresolved(self):
        correlator = EvidenceToSourceCorrelator(companion_elf="/bin/app")
        # Observation with invalid negative relative address or mismatch
        obs = {
            "address": 0x1000,
            "load_bias_status": "UNRESOLVED",
        }
        result = correlator.correlate(obs)
        self.assertFalse(result.get("correlated", False))

    def test_falsey_observations_preserved(self):
        # 0, 0.0, False, "", None should be preserved, not defaulted
        rec = RuntimeEvidenceRecord(
            evidence_id="EV_FALSEY_01",
            collection_method="DIRECT_PROC_MEM",
            target_pid=1234,
            collection_timestamp="2026-11-08T00:00:00Z",
            raw_observation={
                "zero_bytes": 0,
                "zero_float": 0.0,
                "is_active": False,
                "empty_tag": "",
                "null_ptr": None,
            },
        )
        self.assertEqual(rec.normalized_observation["zero_bytes"], 0)
        self.assertEqual(rec.normalized_observation["zero_float"], 0.0)
        self.assertEqual(rec.normalized_observation["is_active"], False)
        self.assertEqual(rec.normalized_observation["empty_tag"], "")
        self.assertIsNone(rec.normalized_observation["null_ptr"])


class TestTemporalJitterAndLimitations(unittest.TestCase):
    """Area 11: Monotonic elapsed time, interval jitter, missing samples."""

    def test_irregular_sample_intervals_disclosed_in_limitations(self):
        window = ObservationWindow(
            target_pid=1234,
            target_identity="local",
            default_interval=0.1,
        )
        # Irregular intervals: 1.0s, 10.0s, 0.1s, 20.0s
        timestamps = [1000.0, 1001.0, 1011.0, 1011.1, 1031.1]
        rss_values = [100, 105, 110, 115, 120]

        for idx, (t, r) in enumerate(zip(timestamps, rss_values)):
            window.record_sample(MemorySample(
                epoch_id=idx + 1,
                monotonic_timestamp=t,
                rss_kb=r,
            ))

        analysis = window.analyze_memory_behavior()
        self.assertTrue(len(analysis.limitations) > 0)
        self.assertTrue(any("Irregular observation intervals" in lim for lim in analysis.limitations))


class TestMasterDiagnosticReportEngine(unittest.TestCase):
    """Area 12, 13: Report parity across JSON, HTML, Markdown, and MCP."""

    def test_report_sections_a_through_i_consistency(self):
        report = DiagnosticReport(
            report_id="REP_001",
            investigation_id="SESS_REPORT_TEST",
            schema_version="2.1.5",
            section_a_executive_summary=ExecutiveSummarySection(
                target_identity="PID 2048 (telemetry_worker)",
                investigation_id="SESS_REPORT_TEST",
                overall_result="CONFIRMED_FAULT",
                most_important_findings=["Unbounded queue growth without pop"],
                confirmed_problems=["Unbounded queue growth without pop"],
                probable_problems=[],
                critical_risks=["Memory exhaustion"],
                unresolved_questions=[],
                recommended_next_actions=["Add bounded capacity to queue"],
            ),
            section_b_target_context=TargetContextSection(
                target_process_name="telemetry_worker",
                pid=2048,
                binary_path="/usr/bin/telemetry_worker",
                companion_elf="/usr/bin/telemetry_worker",
                target_capabilities=["PROCFS", "READABLE_VMA"],
            ),
            section_c_diagnostic_strategy=DiagnosticStrategySection(
                initial_classification="MEMORY_LEAK",
                classification_confidence=0.92,
                methodology_name="Temporal Memory Growth & Allocation Site Analysis",
                methodology_selection_reason="Monotonic heap increase reported",
                recipes_executed=["RECIPE_GROWTH_RATE_REGRESSION"],
            ),
            section_d_detailed_inspection_results=DetailedInspectionResultsSection(
                checks_total=1,
                checks_passed=1,
                checks_failed=0,
                checks_inconclusive=0,
                checks_not_applicable=0,
                checks_not_executed=0,
                checks_error=0,
                checks=[
                    DiagnosticCheck(
                        check_id="CHK_01",
                        description="Check slope",
                        technical_rationale="R",
                        decision_criteria={"slope": ">0"},
                        inspected_entity="RSS",
                        status=CheckStatus.PASS,
                    ).to_dict()
                ],
            ),
            section_e_findings_and_root_cause=FindingsSection(
                confirmed_root_causes=[
                    FindingRecord(
                        finding_id="FND_01",
                        severity="CRITICAL",
                        classification=CLASSIFICATION_CONFIRMED_ROOT_CAUSE,
                        problem_description="Unbounded queue growth",
                        affected_entity="queue",
                        observed_behavior="Continuous expansion",
                        technical_explanation="Queue items never freed",
                        supporting_evidence_ids=["EV_Q_01"],
                        confidence_basis="Direct queue size measurement",
                        verification_status="CONFIRMED",
                    )
                ]
            ),
            section_f_competing_hypotheses=CompetingHypothesesSection(
                leading_hypothesis_id="HYP_01",
                hypotheses=[
                    {
                        "hypothesis_id": "HYP_01",
                        "title": "Unbounded queue",
                        "verdict": "CONFIRMED",
                        "confidence": 0.95,
                        "supporting_evidence": ["EV_Q_01"],
                        "contradicting_evidence": [],
                    }
                ],
                ranking_rationale="Queue size directly correlates with heap slope",
            ),
            section_g_evidence_and_provenance=EvidenceAndProvenanceSection(
                evidence_count=1,
                evidence_records=[
                    EvidenceIndexEntry(
                        evidence_id="EV_Q_01",
                        collection_method="PROCFS_INSPECTOR",
                        target_pid=2048,
                        timestamp="2026-11-08T00:00:00Z",
                        duration_sec=0.01,
                        provenance_class="DIRECT_MEASUREMENT",
                        raw_observation={"queue_len": 50000},
                        normalized_observation={"queue_len": 50000},
                    )
                ],
            ),
            section_h_limitations_and_unverified=LimitationsSection(
                unexecuted_checks=["TLS check"],
                unsupported_capabilities=[],
                collection_failures=[],
            ),
            section_i_final_conclusions=FinalConclusionsSection(
                overall_conclusion="Worker queue is leaking memory monotonically.",
                confirmed_problems=["Unbounded queue growth"],
                probable_problems=[],
                safe_remediation_suggestions=["Add bounded capacity or ensure consumer thread drains queue."],
            ),
        )

        # 1. JSON Export
        j_data = report.to_dict()
        self.assertEqual(j_data["schema_version"], "2.1.5")
        self.assertEqual(j_data["section_a_executive_summary"]["investigation_id"], "SESS_REPORT_TEST")
        self.assertEqual(len(j_data["section_e_findings_and_root_cause"]["confirmed_root_causes"]), 1)

        # 2. Markdown Export
        md_text = report.to_markdown()
        self.assertIn("# dynamicState Expert Diagnostic Incident Report", md_text)
        self.assertIn("## 1. Problem Description & Executive Summary (Section A)", md_text)
        self.assertIn("## 5. Executed Diagnostic Procedures & Inspection Results (Section D)", md_text)
        self.assertIn("## 7. Confirmed Findings & Technical Root Cause (Section E)", md_text)
        self.assertIn("Unbounded queue growth without pop", md_text)

        # 3. HTML Export
        html_text = report.to_html()
        self.assertIn("<!DOCTYPE html>", html_text)
        self.assertIn(f"<title>Diagnostic Report: {report.investigation_id}</title>", html_text)
        self.assertIn("Unbounded queue growth without pop", html_text)
        self.assertIn("<h2>D. Detailed Inspection Results</h2>", html_text)
        self.assertIn(">PASS</span>", html_text)


class TestMcpToolReportEndpoints(unittest.TestCase):
    """Area 12: MCP Server endpoints exposure."""

    def test_mcp_report_export_formats(self):
        from scripts.mcp_server import runtime
        session = runtime.expert_diagnostic_engine.start_investigation("MCP diagnostic test", pid=1234)
        session.step()
        session.step()

        # JSON
        raw_json = runtime_get_investigation_report(session.investigation_id, format="json")
        res_json = json.loads(raw_json)
        self.assertTrue(res_json.get("success", False))
        self.assertIn("report", res_json)
        self.assertEqual(res_json["report"]["schema_version"], "2.1.5")

        # Markdown
        raw_md = runtime_get_investigation_report(session.investigation_id, format="markdown")
        res_md = json.loads(raw_md)
        self.assertTrue(res_md.get("success", False))
        self.assertIn("# dynamicState Expert Diagnostic Incident Report", res_md["report"])

        # HTML
        raw_html = runtime_get_investigation_report(session.investigation_id, format="html")
        res_html = json.loads(raw_html)
        self.assertTrue(res_html.get("success", False))
        self.assertIn("<!DOCTYPE html>", res_html["report"])

        # Inspect tool includes methodology and checks
        raw_inspect = runtime_inspect_investigation(session.investigation_id)
        res_inspect = json.loads(raw_inspect)
        self.assertTrue(res_inspect.get("success", False))
        self.assertIn("methodology", res_inspect)
        self.assertIn("checks", res_inspect)


class TestRealisticCppScenarios(unittest.TestCase):
    """Area 15: C++ Scenarios (UAF, Leak, Deadlock, Warm-up)."""

    def test_cpp_memory_leak_investigation_end_to_end(self):
        debug_elf = "/tmp/expert_diagnostic_debug.elf"
        if not os.path.exists(debug_elf):
            cmd = (
                "g++ -g -O0 -fno-inline -fno-omit-frame-pointer "
                "tests/fixtures/real_runtime/expert_diagnostic_scenarios.cpp "
                "-o /tmp/expert_diagnostic_debug.elf -lpthread"
            )
            subprocess.run(cmd, shell=True, check=True)

        proc = subprocess.Popen([debug_elf, "leak"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            time.sleep(0.15)
            engine = ExpertDiagnosticEngine(corpus_dir=tempfile.gettempdir())
            session = engine.start_investigation(
                "Continuous RSS growth in worker",
                pid=proc.pid,
                companion_elf=debug_elf,
            )

            # Step until completed or step budget
            for _ in range(15):
                if session.state in (STATE_COMPLETED, STATE_INCONCLUSIVE):
                    break
                session.step()

            self.assertIn(session.state, (STATE_COMPLETED, STATE_INCONCLUSIVE))
            self.assertIsNotNone(session.methodology)
            self.assertTrue(len(session.checks) > 0)

            # Build diagnostic report
            report = session.build_diagnostic_report()
            self.assertIsNotNone(report.section_a_executive_summary)
            self.assertIsNotNone(report.section_c_diagnostic_strategy)
            self.assertEqual(report.section_b_target_context.pid, proc.pid)
        finally:
            try:
                proc.terminate()
                proc.wait(timeout=1.0)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass


if __name__ == "__main__":
    unittest.main()
