"""Focused regression tests for the P0 enforcement and P1 integrity closure."""

import os
import shutil
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from extractor.debug_image import inspect_elf
from extractor.diagnostic_report import (
    DiagnosticReport,
    EvidenceAndProvenanceSection,
    EvidenceIndexEntry,
    FindingRecord,
    FindingsSection,
)
from extractor.ebpf_tracer import (
    EbpfTracer,
    runtime_to_elf_address,
    target_identity_matches,
)
from extractor.expert_diagnostic_engine import AdaptiveInvestigationSession
from extractor.capture_backend import OperationLifecycleState
from extractor.capture_backend import CausalAttestation, DurableTrustStore
from extractor.target_adapter import LocalTargetAdapter


class TestTraceIdentityAndElfAddresses(unittest.TestCase):
    def test_build_id_mismatch_fails_before_tracing(self):
        if not os.path.exists("/bin/echo"):
            self.skipTest("/bin/echo is unavailable")
        session = EbpfTracer(use_sudo=False).trace(
            pid=os.getpid(), binary_path="/bin/echo", function_name="main", duration_s=0.1
        )
        self.assertEqual(session.status, "FAILED")
        self.assertEqual(session.build_id_status, "MISMATCHED")
        self.assertIn("Build ID", session.error_message)

    def test_pid_reuse_is_identity_change(self):
        identity = {
            "host_identity": "host", "boot_id": "boot", "pid": 42,
            "process_start_time": 100, "executable_path": "/bin/echo",
            "executable_device": 1, "executable_inode": 2, "build_id": "abc",
        }
        reused = dict(identity, process_start_time=101)
        self.assertFalse(target_identity_matches(identity, reused))

    @unittest.skipUnless(shutil.which("gcc") and shutil.which("addr2line"), "gcc/addr2line unavailable")
    def test_pie_and_non_pie_runtime_addresses_resolve_to_known_source(self):
        source = """\n__attribute__((noinline)) int source_probe(int x) { return x + 7; }\nint main(void) { return source_probe(1); }\n"""
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "fixture.c")
            with open(src, "w", encoding="utf-8") as fh:
                fh.write(source)
            for name, flags, expected_type, bias in (
                ("pie", ["-fPIE", "-pie"], "ET_DYN", 0x700000000000),
                ("nopie", ["-fno-pie", "-no-pie"], "ET_EXEC", 0),
            ):
                binary = os.path.join(tmp, name)
                subprocess.run(["gcc", "-g", "-O0", "-fno-inline", *flags, src, "-o", binary],
                               check=True, capture_output=True)
                elf = inspect_elf(binary)
                self.assertEqual(elf.elf_type, expected_type)
                symbols = subprocess.run(["nm", "-n", binary], check=True, text=True,
                                         capture_output=True).stdout
                symbol = next(line for line in symbols.splitlines() if line.endswith(" source_probe"))
                elf_addr = int(symbol.split()[0], 16)
                page = os.sysconf("SC_PAGE_SIZE")
                load = next(seg for seg in elf.pt_loads
                            if (int(seg["p_vaddr"]) <= elf_addr <
                                int(seg["p_vaddr"]) + int(seg["p_memsz"])))
                map_start = bias + (int(load["p_vaddr"]) & ~(page - 1))
                map_offset = int(load["p_offset"]) & ~(page - 1)
                runtime = bias + elf_addr
                maps = (f"{map_start:x}-{map_start + 0x10000:x} r-xp "
                        f"{map_offset:08x} 08:01 123 {binary}\n")
                resolved = runtime_to_elf_address(runtime, binary, elf, maps)
                self.assertEqual(resolved, elf_addr)
                line = subprocess.run(["addr2line", "-f", "-e", binary, f"0x{resolved:x}"],
                                      check=True, text=True, capture_output=True).stdout
                self.assertIn("source_probe", line)
                self.assertIn("fixture.c:2", line)


class TestReportEvidenceAdmission(unittest.TestCase):
    def test_missing_or_unaccepted_evidence_cannot_render_as_a_confirmed_cause(self):
        finding = FindingRecord(
            finding_id="cause-1", severity="HIGH", classification="CONFIRMED_ROOT_CAUSE",
            problem_description="candidate", supporting_evidence_ids=["missing-evidence"],
            verification_status="CONFIRMED",
        )
        report = DiagnosticReport(
            report_id="report-1", investigation_id="investigation-1",
            section_e_findings_and_root_cause=FindingsSection(confirmed_root_causes=[finding]),
        )
        for render in (report.to_dict, report.to_markdown, report.to_html):
            with self.assertRaisesRegex(ValueError, "missing or unaccepted evidence"):
                render()

    def test_unaccepted_index_entry_is_rejected_and_accepted_rendering_is_immutable(self):
        rejected = EvidenceIndexEntry(
            evidence_id="rejected-evidence", collection_method="test", target_pid=42,
            timestamp="now", duration_sec=0.0, provenance_class="UNTRUSTED",
            raw_observation="raw", normalized_observation="normalized", authority_status="REJECTED",
        )
        rejected_report = DiagnosticReport(
            report_id="r", investigation_id="i",
            section_g_evidence_and_provenance=EvidenceAndProvenanceSection(1, [rejected]),
        )
        with self.assertRaisesRegex(ValueError, "non-authoritative record"):
            rejected_report.to_markdown()

        untrusted_verified = EvidenceIndexEntry(
            evidence_id="untrusted-verified", collection_method="test", target_pid=42,
            timestamp="now", duration_sec=0.0, provenance_class="IMPORTED_UNVERIFIED",
            raw_observation="raw", normalized_observation="normalized", authority_status="VERIFIED",
        )
        with self.assertRaisesRegex(ValueError, "untrusted provenance"):
            DiagnosticReport(report_id="r", investigation_id="i",
                             section_g_evidence_and_provenance=EvidenceAndProvenanceSection(
                                 1, [untrusted_verified])).to_dict()

        accepted = EvidenceIndexEntry(
            evidence_id="accepted-evidence", collection_method="test", target_pid=42,
            timestamp="now", duration_sec=0.0, provenance_class="LIVE_RUNTIME_CAPTURE",
            raw_observation="raw", normalized_observation="normalized", authority_status="VERIFIED",
        )
        report = DiagnosticReport(
            report_id="r", investigation_id="i",
            section_g_evidence_and_provenance=EvidenceAndProvenanceSection(1, [accepted]),
        )
        before = report.to_dict()
        report.to_markdown()
        report.to_html()
        self.assertEqual(report.to_dict(), before)


class TestProductionCaptureTransactionFailurePath(unittest.TestCase):
    def test_mandatory_capture_fails_closed_without_lifecycle_store(self):
        adapter = LocalTargetAdapter()
        adapter.trust_store = None
        with patch("extractor.capture_backend.get_default_trust_store", return_value=None):
            with self.assertRaisesRegex(RuntimeError, "requires durable lifecycle persistence"):
                adapter.begin_capture_transaction(
                    session_id="session", pid=os.getpid(), require_lifecycle_persistence=True
                )
        self.assertEqual(adapter._active_transactions, {})
        self.assertEqual(adapter._active_by_scope, {})

    def _session(self, collect_error):
        session = AdaptiveInvestigationSession.__new__(AdaptiveInvestigationSession)
        session.budget_tracker = None
        session.plan = SimpleNamespace(
            current_step_index=0,
            steps=[SimpleNamespace(status="PENDING", recipe_id="recipe", step_id="step-1",
                                   default_check=False, executed_at=None)],
        )
        session.checks = []
        session.recipe_registry = SimpleNamespace(get_recipe=lambda _rid: SimpleNamespace(
            recipe_id="recipe", version="1", name="test", domain="test",
            required_prerequisites=[], applicable_target_capabilities=[],
            thresholds_and_conditions={}, required_evidence=[],
        ))
        session.methodology = None
        session.pid = os.getpid()
        session.temporal_memory_samples = []
        session.ledger = SimpleNamespace(session_id="session")
        session.investigation_id = "investigation"
        session.companion_elf = None
        session.target_assessment = None
        session.classification_result = None
        tx = SimpleNamespace(require_lifecycle_persistence=True)
        session.adapter = SimpleNamespace(
            get_process_status=lambda _pid: {},
            begin_capture_transaction=Mock(return_value=tx),
            rollback_capture_transaction=Mock(),
            commit_capture_transaction=Mock(),
        )
        session.evidence_provider = SimpleNamespace(
            collect_for_recipe=Mock(side_effect=collect_error)
        )
        return session, tx

    def test_collect_exception_rolls_back_failed_and_never_commits(self):
        session, tx = self._session(ValueError("collection failed"))
        with self.assertRaisesRegex(ValueError, "collection failed"):
            session._step_collect_next()
        session.adapter.begin_capture_transaction.assert_called_once()
        self.assertTrue(session.adapter.begin_capture_transaction.call_args.kwargs[
            "require_lifecycle_persistence"])
        session.adapter.commit_capture_transaction.assert_not_called()
        self.assertEqual(session.adapter.rollback_capture_transaction.call_args.kwargs["terminal_state"],
                         OperationLifecycleState.FAILED)

    def test_cancellation_rolls_back_cancelled_and_never_commits(self):
        import asyncio
        session, _tx = self._session(asyncio.CancelledError())
        with self.assertRaises(asyncio.CancelledError):
            session._step_collect_next()
        session.adapter.commit_capture_transaction.assert_not_called()
        self.assertEqual(session.adapter.rollback_capture_transaction.call_args.kwargs["terminal_state"],
                         OperationLifecycleState.CANCELLED)


class TestAttestationCanonicalDigest(unittest.TestCase):
    def _attestation(self, attestation_id):
        attestation = CausalAttestation(
            attestation_id=attestation_id, session_id="session", operation_id="operation-1",
            target_identity={"pid": 42, "process_identity": "host:boot:42:100",
                             "executable_identity": "/bin/test", "build_id": "sha1:test"},
            precondition_evidence_id="before", postcondition_evidence_id="after",
            claimed_transition={"state": "before", "to": "after"},
            issued_at_ns=1, expires_at_ns=0,
        )
        attestation.sign("test-secret")
        return attestation

    def test_consumption_rejects_missing_or_inconsistent_rfc8785_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = DurableTrustStore(os.path.join(tmp, "trust.json"))
            missing = self._attestation("att-missing-digest")
            missing.canonical_digest = ""
            result = store.consume_attestation(
                missing, "evidence-missing", session_id="session", expected_pid=42,
                expected_process_identity="host:boot:42:100", expected_executable_identity="/bin/test",
                expected_build_id="sha1:test", operation_id="operation-1", secret="test-secret",
            )
            self.assertFalse(result.is_accepted)
            self.assertFalse(store.is_attestation_used(missing.attestation_id))

            mismatched = self._attestation("att-mismatched-digest")
            mismatched.claimed_transition["to"] = "tampered"
            result = store.consume_attestation(
                mismatched, "evidence-mismatched", session_id="session", expected_pid=42,
                expected_process_identity="host:boot:42:100", expected_executable_identity="/bin/test",
                expected_build_id="sha1:test", operation_id="operation-1", secret="test-secret",
            )
            self.assertFalse(result.is_accepted)
            self.assertFalse(store.is_attestation_used(mismatched.attestation_id))

            valid = self._attestation("att-valid-digest")
            result = store.consume_attestation(
                valid, "evidence-valid", session_id="session", expected_pid=42,
                expected_process_identity="host:boot:42:100", expected_executable_identity="/bin/test",
                expected_build_id="sha1:test", operation_id="operation-1", secret="test-secret",
            )
            self.assertTrue(result.is_accepted)


if __name__ == "__main__":
    unittest.main()
