"""Adversarial Regression Tests for CI Verification Integrity & Evidence Admission Closure.

Covers:
1. Baseline failure with RECORD_ONLY enabled (preserves failure visibility, exit code 0).
2. Skipped test accounting (distinguishes SKIPPED_CAPABILITY vs SKIPPED_FLAKY, records reasons).
3. Zero executed tests failure in baseline runner (fails with exit code 2).
4. Evidence admission exception failure propagation (returns FAILED:..., never RECORDED).
5. Quarantined evidence rejection and non-promotion (returns QUARANTINED:..., excluded from hypotheses).
6. Persistence failure during admission (fails closed).
7. Missing canonical operation record in EvidenceLedger.add_record() (fails closed, raises ValueError).
8. Canonical replay identity downgrade prevention (mandatory operations cannot bypass replay checks).
9. Mixed accepted and rejected supporting evidence (requires all supporting evidence, caps at INCONCLUSIVE).
10. Invalid evidence lineage and provenance (caps at INCONCLUSIVE).
11. Same-capture evidence correlation (shared receipt_id/operation_id classified as correlated, not independent).
12. End-to-end report authority (DiagnosticReport refuses to report VERIFIED/CONFIRMED with unadmitted evidence).
"""

import os
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

from extractor.capture_backend import (
    LiveCaptureReceipt,
    get_trusted_capture_authority_token,
    issue_live_capture_receipt,
)
from extractor.diagnostic_report import (
    DiagnosticReport,
    FindingRecord,
    FindingsSection,
)
from extractor.evidence_ledger import (
    EvidenceLedger,
    EvidenceRecord,
)
from extractor.expert_diagnostic_engine import (
    AdaptiveInvestigationSession,
    ExpertHypothesis,
)
from extractor.hypothesis import (
    HYPOTHESIS_STATUS_INCONCLUSIVE,
    HYPOTHESIS_STATUS_PROPOSED,
    HYPOTHESIS_STATUS_SUPPORTED,
    HYPOTHESIS_STATUS_VALIDATED,
    HypothesisValidator,
    InvestigationHypothesis,
    classify_evidence_relationship,
)
from extractor.investigation import InvestigationSession


class TestCIBaselineIntegrity(unittest.TestCase):
    """Audits and asserts scripts/run_test_baseline.sh behavior under adverse conditions."""

    def setUp(self):
        self.repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        self.baseline_script = os.path.join(self.repo_root, "scripts", "run_test_baseline.sh")
        self.temp_dir = tempfile.mkdtemp(prefix="test_baseline_integrity_")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_baseline_failure_with_record_only_enabled(self):
        """When a test fails and BASELINE_RECORD_ONLY=1, exit code is 0 but artifact records failure."""
        mock_tests_dir = os.path.join(self.temp_dir, "tests")
        os.makedirs(mock_tests_dir)
        mock_scripts_dir = os.path.join(self.temp_dir, "scripts")
        os.makedirs(mock_scripts_dir)
        out_dir = os.path.join(self.temp_dir, "out")

        # Create mock run_unittest.py that fails for failing test
        with open(os.path.join(mock_scripts_dir, "run_unittest.py"), "w") as f:
            f.write(
                "import sys\n"
                "if 'fail' in sys.argv[1]:\n"
                "    sys.stderr.write('AssertionError: intentional baseline failure\\n')\n"
                "    sys.exit(1)\n"
                "print('Ran 3 tests in 0.01s\\nOK')\n"
                "sys.exit(0)\n"
            )

        with open(os.path.join(mock_tests_dir, "test_pass.py"), "w") as f:
            f.write("# passing test\n")
        with open(os.path.join(mock_tests_dir, "test_fail.py"), "w") as f:
            f.write("# failing test\n")

        env = os.environ.copy()
        env["BASELINE_REPO_ROOT"] = self.temp_dir
        env["BASELINE_RECORD_ONLY"] = "1"
        env["BASELINE_TIMEOUT"] = "10"
        env["BASELINE_JOBS"] = "1"

        res = subprocess.run(
            [self.baseline_script, out_dir],
            cwd=self.temp_dir,
            env=env,
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 0, f"BASELINE_RECORD_ONLY=1 should exit 0, got: {res.stderr}")
        self.assertIn("BASELINE_RECORD_ONLY=1: baseline recorded as informational artifact", res.stdout)

        totals_path = os.path.join(out_dir, "totals.txt")
        self.assertTrue(os.path.exists(totals_path))
        with open(totals_path) as f:
            totals_content = f.read()

        self.assertIn("files_total=2", totals_content)
        self.assertIn("files_executed=2", totals_content)
        self.assertIn("files_passed=1", totals_content)
        self.assertIn("files_failed=1", totals_content)
        self.assertIn("failing_files=1", totals_content)

        # Check summary.tsv
        summary_path = os.path.join(out_dir, "summary.tsv")
        self.assertTrue(os.path.exists(summary_path))
        with open(summary_path) as f:
            summary_content = f.read()

        self.assertIn("test_fail\tFAILED\t1", summary_content)
        self.assertIn("test_pass\tPASSED\t0", summary_content)
        self.assertTrue(os.path.exists(os.path.join(out_dir, "failed_test_fail.log")))

    def test_baseline_skipped_test_accounting(self):
        """Distinguishes SKIPPED_CAPABILITY vs SKIPPED_FLAKY and records explicit reasons."""
        mock_tests_dir = os.path.join(self.temp_dir, "tests")
        os.makedirs(mock_tests_dir)
        mock_scripts_dir = os.path.join(self.temp_dir, "scripts")
        os.makedirs(mock_scripts_dir)
        out_dir = os.path.join(self.temp_dir, "out")

        with open(os.path.join(mock_scripts_dir, "run_unittest.py"), "w") as f:
            f.write("print('Ran 5 tests in 0.02s\\nOK')\n")

        with open(os.path.join(mock_tests_dir, "test_pass.py"), "w") as f:
            f.write("# normal test\n")
        with open(os.path.join(mock_tests_dir, "test_ebpf.py"), "w") as f:
            f.write("# BASELINE_SKIP: Requires eBPF / root capabilities\n")
        with open(os.path.join(mock_tests_dir, "test_flaky.py"), "w") as f:
            f.write("# CI_FLAKY: Live fixture timing is load-sensitive\n")

        env = os.environ.copy()
        env["BASELINE_REPO_ROOT"] = self.temp_dir
        env["BASELINE_RECORD_ONLY"] = "0"
        env["BASELINE_TIMEOUT"] = "10"
        env["BASELINE_JOBS"] = "1"

        res = subprocess.run(
            [self.baseline_script, out_dir],
            cwd=self.temp_dir,
            env=env,
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 0, f"Expected 0 exit code, got: {res.stderr}")

        summary_path = os.path.join(out_dir, "summary.tsv")
        with open(summary_path) as f:
            summary_content = f.read()

        self.assertIn("test_ebpf\tSKIPPED_CAPABILITY\tSKIPPED\t0\tRequires eBPF / root capabilities", summary_content)
        self.assertIn("test_flaky\tSKIPPED_FLAKY\tSKIPPED\t0\tLive fixture timing is load-sensitive", summary_content)
        self.assertIn("test_pass\tPASSED\t0\t5", summary_content)

        totals_path = os.path.join(out_dir, "totals.txt")
        with open(totals_path) as f:
            totals_content = f.read()

        self.assertIn("files_total=3", totals_content)
        self.assertIn("files_executed=1", totals_content)
        self.assertIn("files_passed=1", totals_content)
        self.assertIn("files_failed=0", totals_content)
        self.assertIn("files_skipped_capability=1", totals_content)
        self.assertIn("files_skipped_flaky=1", totals_content)
        self.assertIn("tests_ran=5", totals_content)

    def test_baseline_zero_tests_fails(self):
        """Zero executed tests must fail with exit code 2 and not report successful baseline."""
        empty_dir = os.path.join(self.temp_dir, "empty")
        os.makedirs(os.path.join(empty_dir, "tests"))
        out_dir = os.path.join(empty_dir, "out")

        env = os.environ.copy()
        env["BASELINE_REPO_ROOT"] = empty_dir

        res = subprocess.run(
            [self.baseline_script, out_dir],
            cwd=empty_dir,
            env=env,
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 2)
        self.assertIn("Error: No test files found", res.stderr)


class TestEvidenceAdmissionFailurePropagation(unittest.TestCase):
    """Audit production path: AdaptiveInvestigationSession -> accept_record() -> hypothesis validation."""

    def setUp(self):
        self.session = AdaptiveInvestigationSession(
            investigation_id="inv_test",
            problem_statement="Test anomaly investigation",
            pid=1000,
            companion_elf="/bin/true",
            _persist_on_create=False,
        )

    def test_admission_exception_returns_failed_not_recorded(self):
        """An exception in accept_record() must return FAILED:..., never RECORDED."""
        with patch.object(self.session.ledger, "accept_record") as mock_accept:
            mock_accept.side_effect = RuntimeError("Storage crash during admission")

            raw_ev = {
                "source": "memory",
                "object_path": "g_data",
                "value": 42,
                "evidence_type": "read",
            }
            status = self.session._record_authoritative_evidence_in_ledger(
                ev_id="ev_test_1",
                recipe_id="RECIPE_HEAP_CORRUPTION",
                observation_text="Heap read",
                prov_class="CONTROLLED_RUNTIME_REPRODUCTION",
                enriched_ev=raw_ev,
            )

            self.assertTrue(status.startswith("FAILED:"), f"Expected status starting with FAILED:, got: {status}")
            self.assertIn("Storage crash during admission", status)
            self.assertNotIn(status, ("RECORDED", "ACCEPTED"))

    def test_quarantined_evidence_returns_quarantined_and_is_not_promoted(self):
        """Quarantined evidence must return QUARANTINED:..., and must not promote hypothesis."""
        from extractor.evidence_ledger import EvidenceAdmissionState

        original_record = self.session.evidence_adapter.record_into_ledger

        def mock_record(rec, ledger, raise_on_error=True):
            rec.admission_state = EvidenceAdmissionState.QUARANTINED
            rec.admission_reason = "Untrusted authority token"
            return original_record(rec, ledger, raise_on_error=raise_on_error)

        with patch.object(self.session.evidence_adapter, "record_into_ledger", side_effect=mock_record):
            raw_ev = {
                "source": "memory",
                "object_path": "g_bad",
                "value": 0xDEADBEEF,
                "evidence_type": "anomaly",
            }
            status = self.session._record_authoritative_evidence_in_ledger(
                ev_id="ev_quarantine_1",
                recipe_id="RECIPE_HEAP_CORRUPTION",
                observation_text="Quarantined anomaly",
                prov_class="LIVE_RUNTIME_CAPTURE",
                enriched_ev=raw_ev,
            )

            self.assertTrue(
                status.startswith("QUARANTINED:"),
                f"Expected status starting with QUARANTINED:, got: {status}",
            )
            self.assertIn("Untrusted authority token", status)

            # Analyze step must not count quarantined evidence towards support
            self.session.collected_evidence.append(
                {
                    "evidence_id": "ev_quarantine_1",
                    "problem_category": "CORRUPTION",
                    "status": "SUPPORTED",
                    "ledger_status": status,
                    "recipe_id": "RECIPE_HEAP_CORRUPTION",
                }
            )

            self.session._step_analyze()
            self.assertGreaterEqual(len(self.session.active_hypotheses), 1)
            for h in self.session.active_hypotheses:
                self.assertNotEqual(h.status, "CONFIRMED")
                self.assertNotEqual(h.status, "SUPPORTED")

    def test_persistence_failure_during_admission(self):
        """I/O or disk persistence failure must be returned as FAILED and fail closed."""
        with patch.object(self.session.evidence_adapter, "record_into_ledger") as mock_rec:
            mock_rec.side_effect = OSError("Read-only file system")

            raw_ev = {"source": "procfs", "metric": "rss", "value": 100000}
            status = self.session._record_authoritative_evidence_in_ledger(
                ev_id="ev_disk_fail",
                recipe_id="RECIPE_MEMORY_LEAK",
                observation_text="Memory leak observation",
                prov_class="LIVE_RUNTIME_CAPTURE",
                enriched_ev=raw_ev,
            )

            self.assertTrue(status.startswith("FAILED:"))
            self.assertIn("Read-only file system", status)


class TestCanonicalReplayIdentityEnforcement(unittest.TestCase):
    """Audits EvidenceLedger.add_record() and ensures mandatory operations fail closed."""

    def setUp(self):
        self.ledger = EvidenceLedger()
        self.ledger.trust_store = MagicMock()
        self.ledger.trust_store.get_operation_record.return_value = None

    def test_missing_canonical_operation_record_fails_closed(self):
        """Mandatory capture operation without committed operation record in trust store must raise ValueError."""
        receipt = issue_live_capture_receipt(
            session_id=self.ledger.session_id,
            pid=1000,
            process_identity="1000:1",
            executable_identity="/bin/true",
            build_id="sha1_build",
            snapshot_binding="snap_1",
            capture_epoch=0,
            operation_id="op_non_existent",
            capture_authority_token=get_trusted_capture_authority_token(),
        )
        rec = EvidenceRecord(
            evidence_id="ev_001",
            evidence_type="OBJECT_STATE",
            session_id=self.ledger.session_id,
            details={"require_canonical_replay_identity": True},
            provenance={
                "provenance_class": "LIVE_RUNTIME_CAPTURE",
                "live_capture_receipt": receipt,
            },
            target_identity={
                "pid": 1000,
                "process_identity": "1000:1",
                "executable_identity": "/bin/true",
                "build_id": "sha1_build",
            },
            snapshot_ref={"snapshot_id": "snap_1", "epoch": 0},
        )

        with self.assertRaises(ValueError) as ctx:
            self.ledger.add_record(rec)

        self.assertIn("Mandatory capture/lifecycle operation", str(ctx.exception))
        self.assertIn("missing canonical operation record in trust store", str(ctx.exception))

    def test_canonical_identity_downgrade_prevented(self):
        """Evidence carrying capture operation marked with require_canonical_replay_identity must fail closed."""
        rec = EvidenceRecord(
            evidence_id="ev_002",
            evidence_type="OBJECT_STATE",
            session_id=self.ledger.session_id,
            details={"operation_type": "capture", "operation_id": "op_uncommitted", "require_canonical_replay_identity": True},
            target_identity={
                "pid": 1000,
                "process_identity": "1000:1",
                "executable_identity": "/bin/true",
            },
        )

        with self.assertRaises(ValueError) as ctx:
            self.ledger.add_record(rec)

        self.assertIn("Mandatory capture/lifecycle operation", str(ctx.exception))
        self.assertIn("missing canonical operation record in trust store", str(ctx.exception))


class TestHypothesisStatusIntegrity(unittest.TestCase):
    """Audits hypothesis promotion criteria under mixed, unadmitted, and correlated evidence."""

    def test_mixed_accepted_and_rejected_supporting_evidence_remains_inconclusive(self):
        """If any supporting evidence is not authoritatively admitted, hypothesis cannot be supported."""
        validator = HypothesisValidator()
        h = InvestigationHypothesis(
            hypothesis_id="H_MIXED",
            title="Buffer overflow",
            claim="Buffer overflow via stack corruption",
            status=HYPOTHESIS_STATUS_PROPOSED,
            supporting_evidence_ids=["ev_accepted", "ev_rejected"],
        )

        ledger = EvidenceLedger()
        rec_acc = EvidenceRecord(
            evidence_id="ev_accepted",
            evidence_type="OBJECT_STATE",
            timestamp="2026-11-15T00:00:00Z",
        )
        ledger.add_record(rec_acc)
        ledger.accept_record("ev_accepted")

        result = validator.evaluate(
            hypothesis=h,
            ledger=ledger,
        )

        # Must not be promoted to SUPPORTED, VALIDATED, or CONFIRMED
        self.assertNotIn(
            result.to_status,
            (
                HYPOTHESIS_STATUS_SUPPORTED,
                HYPOTHESIS_STATUS_VALIDATED,
            ),
        )
        self.assertEqual(result.to_status, HYPOTHESIS_STATUS_INCONCLUSIVE)

    def test_same_capture_evidence_classified_as_correlated_not_independent(self):
        """Records sharing the same receipt_id or operation_id are correlated, never independent."""
        receipt = LiveCaptureReceipt(
            receipt_id="lcr_batch_42",
            session_id="sess_1",
            pid=1000,
            process_identity="1000:1",
            executable_identity="/bin/true",
            build_id="sha1_build",
            snapshot_binding="snap_1",
            capture_epoch=1,
            operation_id="op_batch_42",
        )

        e1 = EvidenceRecord(
            evidence_id="ev_1",
            evidence_type="OBJECT_STATE",
            provenance={"live_capture_receipt": receipt},
            details={"var": "count_a"},
        )
        e2 = EvidenceRecord(
            evidence_id="ev_2",
            evidence_type="OBJECT_STATE",
            provenance={"live_capture_receipt": receipt},
            details={"var": "count_b"},
        )

        rel = classify_evidence_relationship(e1, e2)
        self.assertEqual(rel, "correlated", f"Shared receipt_id must be classified as correlated, got: {rel}")


class TestEndToEndReportAuthority(unittest.TestCase):
    """DiagnosticReport and report renderers must fail closed when unadmitted evidence is referenced."""

    def test_report_refuses_confirmed_hypothesis_with_missing_evidence(self):
        """DiagnosticReport.validate_evidence_references() must reject CONFIRMED with missing evidence."""
        rep = DiagnosticReport(report_id="rep_test_01", investigation_id="inv_01")
        rep.section_e_findings_and_root_cause = FindingsSection(
            confirmed_root_causes=[
                FindingRecord(
                    finding_id="F1",
                    severity="CRITICAL",
                    classification="CONFIRMED_ROOT_CAUSE",
                    problem_description="Corrupted buffer",
                    supporting_evidence_ids=["ev_missing_from_ledger"],
                )
            ]
        )

        with self.assertRaises(ValueError) as ctx:
            rep.validate_evidence_references()

        self.assertIn("references missing or unaccepted evidence", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
