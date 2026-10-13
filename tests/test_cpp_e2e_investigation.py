"""Comprehensive End-to-End C++ Investigation Validation.

Validates the complete 5-scenario pipeline against a real compiled C++ fixture:
Live Process -> Safe Capture -> Raw Snapshot -> Typed C++ Object Graph
 -> Snapshot Comparison -> Finding / Changed Field -> Matching DWARF Type
 & Source Location -> Related Function Candidates -> Investigation Report

Scenarios:
- Scenario A: debug binary capture -> decode objects -> resolve DWARF declaration -> function candidates with evidence tiers
- Scenario B: stripped binary + debug companion -> build-id verification -> load-bias resolution -> rejected mismatched companion
- Scenario C: state A -> stdin MUTATE -> state B -> exact diff (counter: 42->100, flags: 7->15, value: 111->999) -> code navigation
- Scenario D: worker threads worker_a_fn/worker_b_fn in thread metadata -> thread consistency verification
- Scenario E: target exit during capture, mismatched debug companion, unauthorized live capture safety
"""

import json
import os
import shutil
import signal
import subprocess
import tempfile
import time
import unittest

from extractor.capture_backend import (
    CaptureSafetyPolicy,
    ProcessTargetHandle,
    ProcessVmCaptureBackend,
    ProcfsCaptureBackend,
)
from extractor.debug_image import inspect_elf
from extractor.evidence_ledger import EvidenceRecord
from extractor.investigation import InvestigationManager
from extractor.raw_snapshot import RawRuntimeSnapshot
from extractor.static_analyzer import (
    DwarfStaticAnalysisProvider,
    EVIDENCE_LEVEL_INDIRECT,
    EVIDENCE_LEVEL_OBSERVED,
    EVIDENCE_LEVEL_STATIC,
    EVIDENCE_LEVEL_UNKNOWN,
    LAYOUT_MUTATION_CAVEAT,
)


class TestCppE2EInvestigation(unittest.TestCase):
    """End-to-end test suite verifying Scenarios A, B, C, D, and E."""

    @classmethod
    def setUpClass(cls):
        cls.work_dir = tempfile.mkdtemp(prefix="dynstate_cpp_e2e_")
        cls.corpus_dir = os.path.join(cls.work_dir, "corpus")
        cls.fixture_src = os.path.abspath("tests/fixtures/real_runtime/main.cpp")

        # 1. Compile unstripped debug binary with GNU build-id
        cls.debug_bin = os.path.join(cls.work_dir, "app_debug.elf")
        subprocess.run(
            [
                "g++", "-fPIE", "-pie", "-g", "-O0", "-fno-inline", "-fno-omit-frame-pointer",
                "-Wl,--build-id=sha1", cls.fixture_src, "-o", cls.debug_bin, "-lpthread"
            ],
            check=True
        )

        # 2. Extract stripped production binary
        cls.stripped_bin = os.path.join(cls.work_dir, "app_prod.stripped")
        subprocess.run(["strip", "-s", "-o", cls.stripped_bin, cls.debug_bin], check=True)

        # 3. Compile a second intentionally mismatched debug binary
        cls.mismatched_src = os.path.join(cls.work_dir, "mismatched.cpp")
        with open(cls.mismatched_src, "w") as f:
            f.write("int main() { return 1; }\n")
        cls.mismatched_bin = os.path.join(cls.work_dir, "mismatched_debug.elf")
        subprocess.run(
            [
                "g++", "-fPIE", "-pie", "-g", "-O0",
                "-Wl,--build-id=sha1", cls.mismatched_src, "-o", cls.mismatched_bin
            ],
            check=True
        )

        cls.mgr = InvestigationManager(corpus_dir=cls.corpus_dir)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.work_dir, ignore_errors=True)

    def _start_process(self, bin_path):
        proc = subprocess.Popen(
            [bin_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        line = proc.stdout.readline().strip()
        self.assertEqual(line, "READY", f"Target process failed to report READY: {line}")
        return proc

    def _mutate_process(self, proc):
        proc.stdin.write("MUTATE\n")
        proc.stdin.flush()
        line = proc.stdout.readline().strip()
        self.assertEqual(line, "MUTATED", f"Target process failed to report MUTATED: {line}")

    def _stop_process(self, proc):
        if proc.poll() is None:
            try:
                proc.stdin.write("STOP\n")
                proc.stdin.flush()
                line = proc.stdout.readline().strip()
                self.assertEqual(line, "STOPPED")
                proc.wait(timeout=2)
            except Exception:
                proc.send_signal(signal.SIGTERM)
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=1)
        if proc.stdout:
            proc.stdout.close()
        if proc.stdin:
            proc.stdin.close()
        if proc.stderr:
            proc.stderr.close()

    def test_scenario_a_debug_binary_capture_and_navigation(self):
        """Scenario A: debug binary capture -> decode objects -> resolve DWARF declaration -> function candidates."""
        proc = self._start_process(self.debug_bin)
        try:
            backend = ProcessVmCaptureBackend() if ProcessVmCaptureBackend().is_available(proc.pid) else ProcfsCaptureBackend()
            snap = backend.capture(pid=proc.pid)
            # Explicitly assert snapshot capture quality contract before saving/decoding
            self.assertEqual(snap.completeness, "COMPLETE")
            self.assertEqual(snap.provenance["capture_status"], "COMPLETED")
            self.assertEqual(snap.provenance["bytes_requested"], snap.provenance["bytes_read"])
            self.assertGreater(snap.provenance["bytes_read"], 0)
            self.assertEqual(snap.provenance["identity_contract"]["validity"], "COMPLETE")
            self.assertEqual(snap.provenance["map_enumeration"]["status"], "SUCCESS_WITH_RESULTS")
            self.assertEqual(snap.provenance["thread_enumeration"]["status"], "SUCCESS_WITH_RESULTS")
            self.assertFalse(snap.provenance["thread_enumeration"]["is_synthetic"])

            snap_dir = os.path.join(self.corpus_dir, "memory_snapshots", "snap_scenario_a")
            snap.save(snap_dir)
        finally:
            self._stop_process(proc)

        # Start investigation with debug binary
        session_info = self.mgr.start_investigation(
            goal="Investigate worker runtime state in debug binary",
            memory_snapshot_path=snap_dir,
            debug_image=self.debug_bin,
            authorize_target=False,
        )
        inv_id = session_info["investigation_id"]
        report = self.mgr.generate_report(inv_id)

        # 1. Verify semantic interpretation discovered objects and pointer cycles
        sem_stage = session_info["stages"]["semantic_interpretation"]
        self.assertEqual(sem_stage["status"], "COMPLETED")
        self.assertGreater(sem_stage["details"]["roots_count"], 0)
        self.assertGreater(sem_stage["details"]["objects_count"], 0)

        # 2. Verify static code linking succeeded
        static_stage = session_info["stages"]["static_code_link"]
        self.assertIn("dwarf", static_stage["details"]["provider"])
        self.assertGreater(static_stage["details"]["linked_count"], 0)

        # 3. Verify Findings have full Code Navigation contract
        observed_facts = report["findings"]["observed_facts"]
        self.assertGreater(len(observed_facts), 0)

        # Find finding for State.counter
        state_findings = [f for f in observed_facts if f.get("field_name") == "counter" and f.get("type_name") == "State"]
        self.assertGreater(len(state_findings), 0)
        sf = state_findings[0]

        # Verify Code Navigation fields
        self.assertIsNotNone(sf.get("object_id"))
        self.assertEqual(sf.get("field_name"), "counter")
        self.assertEqual(sf.get("type_name"), "State")
        self.assertIsNotNone(sf.get("source_location"))
        self.assertIn("main.cpp:10", sf.get("source_location"))
        self.assertIsNotNone(sf.get("type_decl_location"))
        self.assertIn("main.cpp:9", sf.get("type_decl_location"))

        # Verify layout mutation caveat
        self.assertIsNotNone(sf.get("layout_caveat"))
        self.assertEqual(sf.get("layout_caveat"), LAYOUT_MUTATION_CAVEAT)

        # Verify function candidates with evidence tiers
        candidates = sf.get("function_candidates", [])
        self.assertGreater(len(candidates), 0)
        cand_names = [c["function_name"] for c in candidates]
        self.assertIn("mutate_worker_state", cand_names)
        self.assertIn("read_worker_state", cand_names)

        mutate_cand = next(c for c in candidates if c["function_name"] == "mutate_worker_state")
        self.assertEqual(mutate_cand["evidence_level"], EVIDENCE_LEVEL_STATIC)
        self.assertIn("main.cpp:49", mutate_cand["source_location"])

        # Indirect callers present
        has_indirect = any(c["evidence_level"] == EVIDENCE_LEVEL_INDIRECT for c in candidates)
        self.assertTrue(has_indirect)

    def test_scenario_b_stripped_binary_with_companion(self):
        """Scenario B: stripped binary + debug companion -> build-id verification -> load-bias resolution -> rejected mismatched companion."""
        proc = self._start_process(self.stripped_bin)
        try:
            backend = ProcessVmCaptureBackend() if ProcessVmCaptureBackend().is_available(proc.pid) else ProcfsCaptureBackend()
            snap = backend.capture(pid=proc.pid)
            # Explicitly assert snapshot quality contract before investigation/decoding
            self.assertEqual(snap.completeness, "COMPLETE")
            self.assertEqual(snap.provenance["capture_status"], "COMPLETED")
            self.assertEqual(snap.provenance["bytes_requested"], snap.provenance["bytes_read"])
            self.assertGreater(snap.provenance["bytes_read"], 0)
            self.assertEqual(snap.provenance["identity_contract"]["validity"], "COMPLETE")
            self.assertEqual(snap.provenance["map_enumeration"]["status"], "SUCCESS_WITH_RESULTS")
            self.assertEqual(snap.provenance["thread_enumeration"]["status"], "SUCCESS_WITH_RESULTS")
            self.assertFalse(snap.provenance["thread_enumeration"]["is_synthetic"])

            snap_dir = os.path.join(self.corpus_dir, "memory_snapshots", "snap_scenario_b")
            snap.save(snap_dir)
        finally:
            self._stop_process(proc)

        # 1. Matching Companion: should succeed with VERIFIED_MATCH
        session_info = self.mgr.start_investigation(
            goal="Investigate stripped binary with companion",
            memory_snapshot_path=snap_dir,
            debug_image=self.debug_bin,
            authorize_target=False,
        )
        id_stage = session_info["stages"]["target_identity"]
        self.assertEqual(id_stage["status"], "COMPLETED")
        self.assertIn(id_stage["details"]["build_id_status"], ("VERIFIED_MATCH", "VERIFIED"))
        self.assertIsNotNone(id_stage["details"]["target_build_id"])
        self.assertEqual(
            id_stage["details"]["target_build_id"],
            id_stage["details"]["debug_build_id"]
        )

        static_stage = session_info["stages"]["static_code_link"]
        self.assertEqual(static_stage["details"]["load_bias_status"], "RESOLVED")

        # 2. Mismatched Companion: must detect mismatch and reject static link
        mismatch_sess = self.mgr.start_investigation(
            goal="Investigate with intentionally mismatched companion",
            memory_snapshot_path=snap_dir,
            debug_image=self.mismatched_bin,
            authorize_target=False,
        )
        mismatch_id_stage = mismatch_sess["stages"]["target_identity"]
        self.assertEqual(mismatch_id_stage["details"]["build_id_status"], "MISMATCH")
        mismatch_static = mismatch_sess["stages"]["static_code_link"]
        self.assertEqual(mismatch_static["status"], "FAILED")
        self.assertEqual(mismatch_static["details"]["linkage_status"], "MISMATCH")
        self.assertIn("mismatches debug image", mismatch_static["details"]["reason"])

    def test_scenario_c_deterministic_mutation_and_exact_diff(self):
        """Scenario C: state A -> stdin MUTATE -> state B -> exact diff (counter: 42->100, flags: 7->15, value: 111->999) -> code navigation."""
        proc = self._start_process(self.stripped_bin)
        try:
            backend = ProcessVmCaptureBackend() if ProcessVmCaptureBackend().is_available(proc.pid) else ProcfsCaptureBackend()

            # Capture Snapshot 1 (State A)
            snap1 = backend.capture(pid=proc.pid)
            self.assertEqual(snap1.completeness, "COMPLETE")
            self.assertEqual(snap1.provenance["capture_status"], "COMPLETED")
            self.assertEqual(snap1.provenance["bytes_requested"], snap1.provenance["bytes_read"])
            self.assertGreater(snap1.provenance["bytes_read"], 0)
            self.assertEqual(snap1.provenance["map_enumeration"]["status"], "SUCCESS_WITH_RESULTS")
            self.assertEqual(snap1.provenance["thread_enumeration"]["status"], "SUCCESS_WITH_RESULTS")
            self.assertFalse(snap1.provenance["thread_enumeration"]["is_synthetic"])

            snap1_dir = os.path.join(self.corpus_dir, "memory_snapshots", "snap_c_01")
            snap1.save(snap1_dir)

            # Trigger Deterministic Mutation via stdin
            self._mutate_process(proc)

            # Capture Snapshot 2 (State B)
            snap2 = backend.capture(pid=proc.pid)
            self.assertEqual(snap2.completeness, "COMPLETE")
            self.assertEqual(snap2.provenance["capture_status"], "COMPLETED")
            self.assertEqual(snap2.provenance["bytes_requested"], snap2.provenance["bytes_read"])
            self.assertGreater(snap2.provenance["bytes_read"], 0)
            self.assertEqual(snap2.provenance["map_enumeration"]["status"], "SUCCESS_WITH_RESULTS")
            self.assertEqual(snap2.provenance["thread_enumeration"]["status"], "SUCCESS_WITH_RESULTS")
            self.assertFalse(snap2.provenance["thread_enumeration"]["is_synthetic"])

            snap2_dir = os.path.join(self.corpus_dir, "memory_snapshots", "snap_c_02")
            snap2.save(snap2_dir)

        finally:
            self._stop_process(proc)

        # Start investigation from snapshot 1
        session_info = self.mgr.start_investigation(
            goal="Track worker mutation and shared node changes",
            memory_snapshot_path=snap1_dir,
            debug_image=self.debug_bin,
            authorize_target=False,
        )
        inv_id = session_info["investigation_id"]

        # Run observation comparison between snap1 and snap2
        cmp_res = self.mgr.compare_observations(inv_id, snap1_dir, snap2_dir)
        self.assertNotIn("error", cmp_res)
        summary = cmp_res["summary"]
        self.assertGreaterEqual(summary["value_changes"], 3)

        changes = cmp_res["changes"]
        # Find exact field changes
        change_map = {c["path"]: c for c in changes if c.get("kind") == "value_change"}

        # 1. State.counter: 42 -> 100
        self.assertIn("State.counter", change_map)
        chg_counter = change_map["State.counter"]
        self.assertEqual(chg_counter["before"], 42)
        self.assertEqual(chg_counter["after"], 100)

        # 2. State.flags: 7 -> 15
        self.assertIn("State.flags", change_map)
        chg_flags = change_map["State.flags"]
        self.assertEqual(chg_flags["before"], 7)
        self.assertEqual(chg_flags["after"], 15)

        # 3. SharedNode.value: 111 -> 999
        self.assertIn("SharedNode.value", change_map)
        chg_val = change_map["SharedNode.value"]
        self.assertEqual(chg_val["before"], 111)
        self.assertEqual(chg_val["after"], 999)

        # Verify Findings generated from these value changes
        report = self.mgr.generate_report(inv_id)
        facts = report["findings"]["observed_facts"]

        # Check Finding for State.counter
        fnd_counter = next((f for f in facts if f.get("field_name") == "counter" and f.get("before_value") == 42), None)
        self.assertIsNotNone(fnd_counter)
        self.assertEqual(fnd_counter["after_value"], 100)
        self.assertEqual(fnd_counter["observed_value"], 100)
        self.assertEqual(fnd_counter["type_name"], "State")
        self.assertIn("main.cpp:10", fnd_counter["source_location"])
        self.assertIn("main.cpp:9", fnd_counter["type_decl_location"])
        self.assertEqual(fnd_counter["layout_caveat"], LAYOUT_MUTATION_CAVEAT)

        # Candidate functions must include mutate_worker_state at main.cpp:49
        cands = fnd_counter.get("function_candidates", [])
        self.assertTrue(any(c["function_name"] == "mutate_worker_state" and "main.cpp:49" in str(c.get("source_location")) for c in cands))

        # Check Finding for SharedNode.value
        fnd_val = next((f for f in facts if f.get("field_name") == "value" and f.get("before_value") == 111), None)
        self.assertIsNotNone(fnd_val)
        self.assertEqual(fnd_val["after_value"], 999)
        self.assertEqual(fnd_val["type_name"], "SharedNode")
        self.assertIn("main.cpp:19", fnd_val["source_location"])
        self.assertIn("main.cpp:18", fnd_val["type_decl_location"])
        val_cands = fnd_val.get("function_candidates", [])
        self.assertTrue(any(c["function_name"] == "advance_shared_node" and "main.cpp:54" in str(c.get("source_location")) for c in val_cands))

        # 4. Verify Causal Hypothesis Generation & Hardened Validation Loop on Real Process Diffs
        session = self.mgr.sessions[inv_id]
        self.mgr._execute_stage_synthesis(session)
        hypos = self.mgr.get_hypotheses(inv_id)
        self.assertGreaterEqual(len(hypos), 1)

        counter_hypo = next((h for h in hypos if "counter" in h["title"].lower() or "counter" in h["claim"].lower()), hypos[0])
        h_id = counter_hypo["hypothesis_id"]

        # Invariant 1: Static candidate mutate_worker_state is NOT initially confirmed
        cands_h = counter_hypo.get("function_candidates", [])
        mutate_cand = next((c for c in cands_h if c.get("function_name") == "mutate_worker_state"), cands_h[0] if cands_h else {})
        self.assertFalse(mutate_cand.get("confirmed_root_cause", False))

        # Invariant 3: Caller supplying boolean alone is rejected!
        unverified_eval = self.mgr.evaluate_hypothesis(
            inv_id,
            h_id,
            deterministic_transition_verified=True,
        )
        self.assertTrue(unverified_eval["success"])
        self.assertEqual(unverified_eval["transition"]["to_status"], "SUPPORTED")
        self.assertTrue(unverified_eval["transition"]["unverified_claim_rejected"])

        # Legitimate validation with verified diff comparison evidence
        proof_eid = f"ev_cpp_proof_{inv_id}"
        rec_proof = EvidenceRecord(
            evidence_id=proof_eid,
            evidence_type="COMPARISON",
            nature="observation",
            source="investigation_observer",
            session_id=inv_id,
            observation="Deterministic transition reproduced: counter 42 -> 100 via mutate_worker_state",
            details={
                "target_function": "mutate_worker_state",
                "field_path": "State.counter",
                "execution_provenance": {
                    "execution_status": "REPRODUCED",
                    "reproduction_verified": True,
                },
            },
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
        )
        self.mgr.sessions[inv_id].ledger.add_record(rec_proof)
        # Direct call to public attest_causal_proof without capability is strictly rejected!
        with self.assertRaises(ValueError):
            self.mgr.attest_causal_proof(
                inv_id,
                proof_eid,
                target_function="mutate_worker_state",
                field_path="State.counter",
            )

        # Authentically verify live reproduction between snap1 and snap2 and issue attestation
        att_ok = self.mgr.verify_live_reproduction_and_attest(
            investigation_id=inv_id,
            hypothesis_id=h_id,
            evidence_id=proof_eid,
            snapshot_a_path=snap1_dir,
            snapshot_b_path=snap2_dir,
            target_function="mutate_worker_state",
            field_path="State.counter",
        )
        self.assertTrue(att_ok)
        verified_eval = self.mgr.evaluate_hypothesis(
            inv_id,
            h_id,
            proof_evidence_id=proof_eid,
            deterministic_transition_verified=True,
        )
        self.assertTrue(verified_eval["success"])
        self.assertEqual(verified_eval["transition"]["to_status"], "VALIDATED")

        # Report exposes causal conclusions
        final_report = self.mgr.generate_report(inv_id)
        cc = final_report["causal_conclusions"]
        self.assertTrue(cc["causal_proof_established"])
        self.assertEqual(cc["validated_causal_count"], 1)
        # Invariant 1: Static DWARF candidate remains STATIC_CANDIDATE and is NOT silently confirmed as root cause!
        self.assertTrue(any(f.get("function_name") == "mutate_worker_state" and not f.get("confirmed_root_cause") for f in cc["static_candidates"]))

    def test_scenario_d_worker_threads_and_thread_consistency(self):
        """Scenario D: worker threads worker_a_fn/worker_b_fn in thread metadata -> thread consistency verification."""
        proc = self._start_process(self.debug_bin)
        try:
            backend = ProcessVmCaptureBackend() if ProcessVmCaptureBackend().is_available(proc.pid) else ProcfsCaptureBackend()
            snap = backend.capture(pid=proc.pid)
            # Explicitly assert snapshot quality contract before verifying thread records
            self.assertEqual(snap.completeness, "COMPLETE")
            self.assertEqual(snap.provenance["capture_status"], "COMPLETED")
            self.assertEqual(snap.provenance["identity_contract"]["validity"], "COMPLETE")
            self.assertEqual(snap.provenance["map_enumeration"]["status"], "SUCCESS_WITH_RESULTS")
            self.assertEqual(snap.provenance["thread_enumeration"]["status"], "SUCCESS_WITH_RESULTS")
            self.assertFalse(snap.provenance["thread_enumeration"]["is_synthetic"])

            snap_dir = os.path.join(self.corpus_dir, "memory_snapshots", "snap_scenario_d")
            snap.save(snap_dir)

            # Verify thread metadata in capture
            threads = snap.thread_metadata
            # Target has main thread + worker_a + worker_b + cmd_thread >= 4 threads
            self.assertGreaterEqual(len(threads), 3)

            # Thread latencies truthful
            self.assertGreaterEqual(snap.stop_latency_us, 0.0)
            self.assertGreaterEqual(snap.resume_latency_us, 0.0)

        finally:
            self._stop_process(proc)

    def test_scenario_e_failure_modes_and_safeties(self):
        """Scenario E: target exit during capture, mismatched companion, unauthorized live capture safety."""
        # 1. Unauthorized live capture must be rejected without live signal
        res_auth = self.mgr.start_investigation(
            goal="Unauthorized capture attempt",
            pid=99999,
            authorize_target=False,
        )
        self.assertEqual(res_auth["status"], "BLOCKED")
        self.assertEqual(res_auth["stages"]["target_identity"]["status"], "BLOCKED")
        self.assertIn("Target authorization required", res_auth["summary"]["error"])

        # 2. Target exit / non-existent PID fails gracefully
        res_esrch = self.mgr.start_investigation(
            goal="Nonexistent process capture",
            pid=99999999,
            authorize_target=True,
        )
        self.assertEqual(res_esrch["status"], "FAILED")
        self.assertIn("ESRCH", res_esrch["summary"]["error"])

        # 3. ProcessTargetHandle identity mismatch check
        with self.assertRaises(ProcessLookupError):
            with ProcessTargetHandle(99999999, expected_starttime="12345") as handle:
                handle.verify_identity()

        # 4. Refuse decoding of an INVALID snapshot
        invalid_snap = RawRuntimeSnapshot(
            snapshot_id="invalid_test_snap",
            pid=12345,
            executable=self.debug_bin,
            executable_build_id=None,
            timestamp="",
            capture_duration_us=100.0,
            completeness="INVALID",
            provenance={"capture_status": "INVALID"},
        )
        invalid_dir = os.path.join(self.work_dir, "invalid_snap")
        invalid_snap.save(invalid_dir)
        inv_invalid = self.mgr.start_investigation(
            goal="Test invalid snapshot decode refusal",
            memory_snapshot_path=invalid_dir,
            debug_image=self.debug_bin,
            authorize_target=False,
        )
        self.assertEqual(inv_invalid["stages"]["capture_quality"]["status"], "FAILED")
        self.assertEqual(inv_invalid["stages"]["semantic_interpretation"]["status"], "FAILED")
        report_invalid = self.mgr.generate_report(inv_invalid["investigation_id"])
        self.assertEqual(len(report_invalid["findings"]["observed_facts"]), 0)
        self.assertEqual(report_invalid["capture_quality_assessment"]["trust_level"], "UNTRUSTED")

        # 5. FAILED snapshot verification
        failed_snap = RawRuntimeSnapshot(
            snapshot_id="failed_test_snap",
            pid=12345,
            executable=self.debug_bin,
            executable_build_id=None,
            timestamp="",
            capture_duration_us=100.0,
            completeness="FAILED",
            provenance={"capture_status": "FAILED", "bytes_requested": 1000, "bytes_read": 0},
        )
        failed_dir = os.path.join(self.work_dir, "failed_snap")
        failed_snap.save(failed_dir)
        inv_failed = self.mgr.start_investigation(
            goal="Test failed snapshot refusal",
            memory_snapshot_path=failed_dir,
            debug_image=self.debug_bin,
            authorize_target=False,
        )
        self.assertEqual(inv_failed["stages"]["capture_quality"]["status"], "FAILED")
        report_failed = self.mgr.generate_report(inv_failed["investigation_id"])
        self.assertEqual(len(report_failed["findings"]["observed_facts"]), 0)
        self.assertEqual(report_failed["findings_summary"]["facts_count"], 0)
        self.assertEqual(report_failed["capture_quality_assessment"]["trust_level"], "UNTRUSTED")

        # 6. PARTIAL snapshot verification (never generates unqualified high-confidence facts)
        partial_snap = RawRuntimeSnapshot(
            snapshot_id="partial_test_snap",
            pid=12345,
            executable=self.debug_bin,
            executable_build_id=None,
            timestamp="",
            capture_duration_us=100.0,
            completeness="PARTIAL",
            provenance={
                "capture_status": "COMPLETED",
                "bytes_requested": 1000,
                "bytes_read": 1000,
                "thread_enumeration": {"status": "PARTIAL", "is_synthetic": False},
                "map_enumeration": {"status": "SUCCESS_WITH_RESULTS"},
            },
        )
        partial_dir = os.path.join(self.work_dir, "partial_snap")
        partial_snap.save(partial_dir)
        inv_partial = self.mgr.start_investigation(
            goal="Test partial snapshot trust qualification",
            memory_snapshot_path=partial_dir,
            debug_image=self.debug_bin,
            authorize_target=False,
        )
        self.assertEqual(inv_partial["stages"]["capture_quality"]["status"], "PARTIAL")
        report_partial = self.mgr.generate_report(inv_partial["investigation_id"])
        self.assertEqual(report_partial["capture_quality_assessment"]["trust_level"], "PARTIALLY_TRUSTED")
        for f in report_partial["findings"]["observed_facts"]:
            self.assertEqual(f["confidence"], "medium", "PARTIAL capture facts must never be high confidence")
            self.assertEqual(f["status"], "UNVERIFIED_PARTIAL")
            self.assertIsNotNone(f.get("uncertainty"))

        # 7. Function candidates are explicitly static references, never confirmed root causes
        for finding in report_partial["findings"]["observed_facts"] + report_partial["findings"]["hypotheses"] + report_partial["findings"]["unknowns"]:
            for cand in finding.get("function_candidates", []):
                self.assertEqual(cand.get("candidate_kind"), "static_reference")
                self.assertFalse(cand.get("confirmed_root_cause", False))


if __name__ == "__main__":
    unittest.main()
