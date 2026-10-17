"""Comprehensive End-to-End Test Harness for Real Runtime Scenarios (S01 to S12).

Tests dynamicState on a live target process with real C++ structs:
    struct Buffer { uint32_t capacity; uint32_t used; uint8_t data[64]; };
    struct RuntimeState { uint32_t sequence; uint32_t status; Buffer buffer; Buffer* active; };
    RuntimeState g_state;

Verifies:
  - S01 [P0] 실제 필드 주소 및 값 수집
  - S02 [P0] 실제 상태 변화 추적
  - S03 [P0] 변하지 않은 필드 보존
  - S04 [P0] 잘못된 필드 주소
  - S05 [P0] Build ID 불일치
  - S06 [P0] PIE / ASLR load bias
  - S07 [P0] 부분 읽기 및 접근 불가 메모리
  - S08 [P0] 증거 ID 및 출처 위조
  - S09 [P1] Capture gap 및 시간 순서
  - S10 [P1] 포인터 및 객체 그래프 복원
  - S11 [P1] PROT_NONE 가드 페이지 음성 대조군
  - S12 [P1] 조사 결과까지 출처 추적
"""

from datetime import datetime, timezone
import json
import os
import shutil
import struct
import subprocess
import tempfile
import time
from typing import Any, Dict, Optional, Tuple
import unittest

from extractor.capture_backend import ProcessVmCaptureBackend
from extractor.conversational_investigation import ConversationalAnalysisService
from extractor.debug_image import inspect_elf
from extractor.dwarf_indexer import DwarfIndexer
from extractor.evidence_ledger import EvidenceLedger, EvidenceRecord
from extractor.investigation import InvestigationFinding, InvestigationManager, InvestigationSession
from extractor.investigation_quality import QualityMetricsReport
from extractor.semantic_state import OfflineSemanticEngine
from extractor.state_lab import compute_semantic_diff
from extractor.typed_memory_reader import TypedMemoryReader
from extractor.watch_session import CaptureGap, Observation, WatchItem, WatchSessionManager


class TestHarnessScenarios(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work_dir = tempfile.mkdtemp(prefix="dynstate_scenario_harness_")
        cls.corpus_dir = os.path.join(cls.work_dir, "corpus")
        os.makedirs(cls.corpus_dir, exist_ok=True)
        cls.src_path = os.path.abspath("tests/fixtures/real_runtime/scenario_target.cpp")

        # 1. Debug companion binary with DWARF and GNU Build ID
        cls.debug_bin = os.path.join(cls.work_dir, "scenario_target.debug")
        cmd_debug = [
            "g++", "-fPIE", "-pie", "-g", "-O0", "-fno-inline", "-fno-omit-frame-pointer",
            "-Wl,--build-id=sha1", cls.src_path, "-o", cls.debug_bin, "-lpthread"
        ]
        subprocess.run(cmd_debug, check=True)

        # 2. Production target binary (stripped from the same build)
        cls.stripped_bin = os.path.join(cls.work_dir, "scenario_target.stripped")
        subprocess.run(["strip", "-s", "-o", cls.stripped_bin, cls.debug_bin], check=True)

        # 3. Mismatched debug companion binary (different Build ID / different code)
        cls.mismatched_src = os.path.join(cls.work_dir, "mismatched.cpp")
        with open(cls.mismatched_src, "w") as f:
            f.write("int g_dummy = 123;\nint main() { return 0; }\n")
        cls.mismatched_debug = os.path.join(cls.work_dir, "mismatched_debug.elf")
        cmd_mismatch = [
            "g++", "-fPIE", "-pie", "-g", "-O0",
            "-Wl,--build-id=md5", cls.mismatched_src, "-o", cls.mismatched_debug
        ]
        subprocess.run(cmd_mismatch, check=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.work_dir, ignore_errors=True)

    def _start_target(self, bin_path: Optional[str] = None) -> Tuple[subprocess.Popen, Dict[str, Any]]:
        """Start target process and parse explicit synchronization line containing independent oracle addresses."""
        if bin_path is None:
            bin_path = self.stripped_bin
        proc = subprocess.Popen(
            [bin_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        ready_line = proc.stdout.readline().strip()
        tokens = ready_line.split()
        self.assertTrue(ready_line.startswith("READY"), f"Target failed to report READY: {ready_line}")

        oracle: Dict[str, Any] = {}
        for tok in tokens[1:]:
            if "=" in tok:
                k, v = tok.split("=", 1)
                oracle[k] = int(v, 16) if v.startswith("0x") else int(v)
        return proc, oracle

    def _send_cmd(self, proc: subprocess.Popen, cmd: str) -> str:
        """Send command to target process and receive synchronous acknowledgment."""
        proc.stdin.write(cmd.strip() + "\n")
        proc.stdin.flush()
        return proc.stdout.readline().strip()

    def _stop_target(self, proc: subprocess.Popen):
        """Cleanly terminate target process."""
        if proc and proc.poll() is None:
            try:
                proc.stdin.write("STOP\n")
                proc.stdin.flush()
                proc.wait(timeout=2.0)
            except Exception:
                proc.kill()
                proc.wait(timeout=1.0)
        if proc:
            for s in (proc.stdin, proc.stdout, proc.stderr):
                if s and not s.closed:
                    try:
                        s.close()
                    except Exception:
                        pass

    # -------------------------------------------------------------------------
    # S01 [P0] 실제 필드 주소 및 값 수집
    # -------------------------------------------------------------------------
    def test_S01_actual_field_address_and_value_collection(self):
        """S01: Collect field addresses, sizes, bytes, and decode values matching independent oracle."""
        proc, oracle = self._start_target()
        try:
            backend = ProcessVmCaptureBackend()
            snap = backend.capture(pid=proc.pid)
            self.assertEqual(snap.capture_backend, "process_vm_readv")
            self.assertFalse(snap.provenance.get("synthetic", False))

            engine = OfflineSemanticEngine()
            state = engine.reconstruct(raw_snapshot=snap, debug_image=self.debug_bin)

            oracle_seq_addr = oracle["sequence"]
            oracle_stat_addr = oracle["status"]

            # Locate reconstructed g_state object
            g_state_obj = next((o for o in state.objects if "g_state" in (o.get("primary_path") or "")), None)
            self.assertIsNotNone(g_state_obj, "g_state object must be reconstructed from DWARF")

            # 1. Verify sequence field
            seq_field = next((f for f in g_state_obj["fields"] if f.get("name") == "sequence"), None)
            self.assertIsNotNone(seq_field, "g_state.sequence field must be resolved")
            self.assertEqual(int(seq_field["address"], 16), oracle_seq_addr, "Resolved sequence address must match oracle")
            self.assertEqual(seq_field["type"], "uint32_t")
            self.assertEqual(seq_field["value"], 42)
            self.assertEqual(seq_field["status"], "RESOLVED")

            # Verify actual bytes in captured memory buffer
            reader = TypedMemoryReader(snap)
            seq_bytes, st_seq = reader.read(oracle_seq_addr, 4)
            self.assertEqual(st_seq, "COMPLETE")
            self.assertEqual(seq_bytes, struct.pack("<I", 42))

            # 2. Verify status field
            stat_field = next((f for f in g_state_obj["fields"] if f.get("name") == "status"), None)
            self.assertIsNotNone(stat_field, "g_state.status field must be resolved")
            self.assertEqual(int(stat_field["address"], 16), oracle_stat_addr, "Resolved status address must match oracle")
            self.assertEqual(stat_field["type"], "uint32_t")
            self.assertEqual(stat_field["value"], 1)
            self.assertEqual(stat_field["status"], "RESOLVED")

            stat_bytes, st_stat = reader.read(oracle_stat_addr, 4)
            self.assertEqual(st_stat, "COMPLETE")
            self.assertEqual(stat_bytes, struct.pack("<I", 1))

            # 3. Negative check: Arbitrary address substitution
            fake_addr = oracle_seq_addr + 2
            fake_bytes, _ = reader.read(fake_addr, 4)
            self.assertNotEqual(fake_bytes, struct.pack("<I", 42), "Arbitrary misaligned address must not match expected value")
        finally:
            self._stop_target(proc)

    # -------------------------------------------------------------------------
    # S02 [P0] 실제 상태 변화 추적
    # -------------------------------------------------------------------------
    def test_S02_actual_state_transition_tracking(self):
        """S02: Track real state transition 100->101, 1->2 with verifiable chronological diff."""
        proc, oracle = self._start_target()
        try:
            backend = ProcessVmCaptureBackend()
            engine = OfflineSemanticEngine()

            # Step 1: Initial state (100, 1)
            self.assertEqual(self._send_cmd(proc, "SET sequence 100"), "OK sequence=100")
            self.assertEqual(self._send_cmd(proc, "SET status 1"), "OK status=1")

            snap1 = backend.capture(pid=proc.pid)
            state1 = engine.reconstruct(raw_snapshot=snap1, debug_image=self.debug_bin)

            obj1 = next(o for o in state1.objects if "g_state" in (o.get("primary_path") or ""))
            f_seq1 = next(f for f in obj1["fields"] if f["name"] == "sequence")
            f_stat1 = next(f for f in obj1["fields"] if f["name"] == "status")
            self.assertEqual(f_seq1["value"], 100)
            self.assertEqual(f_stat1["value"], 1)

            # Step 2: Mutate state (101, 2)
            self.assertEqual(self._send_cmd(proc, "SET sequence 101"), "OK sequence=101")
            self.assertEqual(self._send_cmd(proc, "SET status 2"), "OK status=2")

            snap2 = backend.capture(pid=proc.pid)
            state2 = engine.reconstruct(raw_snapshot=snap2, debug_image=self.debug_bin)

            obj2 = next(o for o in state2.objects if "g_state" in (o.get("primary_path") or ""))
            f_seq2 = next(f for f in obj2["fields"] if f["name"] == "sequence")
            f_stat2 = next(f for f in obj2["fields"] if f["name"] == "status")
            self.assertEqual(f_seq2["value"], 101)
            self.assertEqual(f_stat2["value"], 2)

            # Step 3: Compute semantic diff
            diff = compute_semantic_diff(state1, state2)
            changed_map = {c["field"]: c for c in diff["changed"]}

            self.assertIn("sequence", changed_map)
            self.assertEqual(changed_map["sequence"]["old_value"], 100)
            self.assertEqual(changed_map["sequence"]["new_value"], 101)

            self.assertIn("status", changed_map)
            self.assertEqual(changed_map["status"]["old_value"], 1)
            self.assertEqual(changed_map["status"]["new_value"], 2)

            # Strict chronological check
            self.assertGreaterEqual(snap2.timestamp, snap1.timestamp)
        finally:
            self._stop_target(proc)

    # -------------------------------------------------------------------------
    # S03 [P0] 변하지 않은 필드 보존
    # -------------------------------------------------------------------------
    def test_S03_unchanged_field_preservation(self):
        """S03: Preserve unchanged status field while updating mutated sequence field."""
        proc, oracle = self._start_target()
        try:
            backend = ProcessVmCaptureBackend()
            engine = OfflineSemanticEngine()

            # State A: sequence=101, status=2
            self._send_cmd(proc, "SET sequence 101")
            self._send_cmd(proc, "SET status 2")
            snap_a = backend.capture(pid=proc.pid)
            state_a = engine.reconstruct(raw_snapshot=snap_a, debug_image=self.debug_bin)

            # State B: sequence=102, status=2 (status NOT modified)
            self._send_cmd(proc, "SET sequence 102")
            snap_b = backend.capture(pid=proc.pid)
            state_b = engine.reconstruct(raw_snapshot=snap_b, debug_image=self.debug_bin)

            # Ensure status is actually observed and resolved in state B
            obj_b = next(o for o in state_b.objects if "g_state" in (o.get("primary_path") or ""))
            f_stat_b = next(f for f in obj_b["fields"] if f["name"] == "status")
            self.assertEqual(f_stat_b["value"], 2)
            self.assertEqual(f_stat_b["status"], "RESOLVED")

            # Diff analysis
            diff = compute_semantic_diff(state_a, state_b)
            changed_fields = [c["field"] for c in diff["changed"]]

            self.assertIn("sequence", changed_fields, "sequence must be recorded as changed")
            self.assertNotIn("status", changed_fields, "unchanged status must NOT appear in mutated diff")
        finally:
            self._stop_target(proc)

    # -------------------------------------------------------------------------
    # S04 [P0] 잘못된 필드 주소
    # -------------------------------------------------------------------------
    def test_S04_invalid_field_address_detection(self):
        """S04: Reject assigning invalid or mismatched memory addresses to structured fields."""
        proc, oracle = self._start_target()
        try:
            dwarf_index = DwarfIndexer.get_index(self.debug_bin)
            g_state_var = next((v for v in dwarf_index.global_variables if v.name == "g_state"), None)
            self.assertIsNotNone(g_state_var)

            canon_t = dwarf_index.resolve_canonical_type(g_state_var.type_offset)
            seq_m = next(m for m in canon_t.members if m.name == "sequence")
            self.assertEqual(seq_m.offset, 0, "Sequence must be at offset 0 of g_state")

            # Alternate memory address (buffer.data[0])
            wrong_addr = oracle["buffer"] + 16
            wrong_offset = wrong_addr - oracle["g_state"]
            self.assertNotEqual(wrong_offset, seq_m.offset, "Buffer data address cannot match sequence offset")

            # Evidence grounding validation
            conv = ConversationalAnalysisService()
            session = InvestigationSession(investigation_id="inv_s04", goal="s04", corpus_dir=self.corpus_dir)
            session.findings.append(InvestigationFinding(
                finding_id="fnd_seq",
                title="Observed Sequence",
                description="True sequence at real address",
                category="fact",
                c_type_path="g_state.sequence",
                observed_value=42,
            ))

            grounded, reason = conv._is_fact_grounded(
                {"field_path": "g_state.sequence", "observed_value": "999", "address": hex(wrong_addr), "fact": "Sequence mutated"},
                session=session,
                ledger=session.ledger,
            )
            self.assertFalse(grounded, "Corrupted/wrong address claim must be rejected as ungrounded")
        finally:
            self._stop_target(proc)

    # -------------------------------------------------------------------------
    # S05 [P0] Build ID 불일치
    # -------------------------------------------------------------------------
    def test_S05_build_id_mismatch_rejection(self):
        """S05: Detect and strictly reject companion DWARF with mismatched Build ID."""
        proc, oracle = self._start_target()
        try:
            backend = ProcessVmCaptureBackend()
            snap = backend.capture(pid=proc.pid)

            elf_target = inspect_elf(self.stripped_bin)
            elf_mismatched = inspect_elf(self.mismatched_debug)
            self.assertNotEqual(elf_target.build_id, elf_mismatched.build_id, "Build IDs must be distinct for negative control")

            # 1. OfflineSemanticEngine rejection
            engine = OfflineSemanticEngine()
            state = engine.reconstruct(raw_snapshot=snap, debug_image=self.mismatched_debug, allow_symbol_mismatch=False)
            self.assertEqual(state.provenance.get("status"), "SYMBOL_MISMATCH")
            self.assertEqual(len(state.objects), 0)

            # 2. InvestigationManager rejection
            mgr = InvestigationManager(corpus_dir=self.corpus_dir)
            res = mgr.start_investigation(
                goal="Test Build ID mismatch",
                pid=proc.pid,
                debug_image=self.mismatched_debug,
                authorize_target=True,
            )
            self.assertEqual(res.get("target_identity", {}).get("build_id_status"), "MISMATCH")
            reason = res.get("target_identity", {}).get("build_id_reason", "").lower()
            self.assertTrue("conflicts" in reason or "mismatch" in reason, f"Unexpected reason: {reason}")
        finally:
            self._stop_target(proc)

    # -------------------------------------------------------------------------
    # S06 [P0] PIE / ASLR load bias
    # -------------------------------------------------------------------------
    def test_S06_pie_aslr_load_bias_recalculation(self):
        """S06: Recalculate PIE load bias and addresses across independent process executions."""
        backend = ProcessVmCaptureBackend()
        engine = OfflineSemanticEngine()

        # Run 1
        proc1, oracle1 = self._start_target()
        try:
            snap1 = backend.capture(pid=proc1.pid)
            state1 = engine.reconstruct(raw_snapshot=snap1, debug_image=self.debug_bin)
            g_state_1 = next(o for o in state1.objects if "g_state" in (o.get("primary_path") or ""))
            resolved_addr_1 = g_state_1["address"]
            self.assertEqual(resolved_addr_1, oracle1["g_state"], "Run 1 resolved address must match Oracle 1")
        finally:
            self._stop_target(proc1)

        # Run 2
        proc2, oracle2 = self._start_target()
        try:
            snap2 = backend.capture(pid=proc2.pid)
            state2 = engine.reconstruct(raw_snapshot=snap2, debug_image=self.debug_bin)
            g_state_2 = next(o for o in state2.objects if "g_state" in (o.get("primary_path") or ""))
            resolved_addr_2 = g_state_2["address"]
            self.assertEqual(resolved_addr_2, oracle2["g_state"], "Run 2 resolved address must match Oracle 2")

            # Each run resolves to its actual running address
            self.assertEqual(resolved_addr_1, oracle1["g_state"])
            self.assertEqual(resolved_addr_2, oracle2["g_state"])
        finally:
            self._stop_target(proc2)

    # -------------------------------------------------------------------------
    # S07 [P0] 부분 읽기 및 접근 불가 메모리
    # -------------------------------------------------------------------------
    def test_S07_partial_read_and_inaccessible_memory(self):
        """S07: Handle unmapped/PROT_NONE memory cleanly without crash, reporting PARTIAL/UNAVAILABLE."""
        proc, oracle = self._start_target()
        try:
            backend = ProcessVmCaptureBackend()
            snap = backend.capture(pid=proc.pid)
            reader = TypedMemoryReader(snap)

            guard_base = oracle["guard"]
            guard_page = guard_base + 4096

            # 1. Read inside PROT_NONE guard page
            res_guard, st_guard = reader.read(guard_page + 64, 8)
            self.assertIn(st_guard, ("OUTSIDE_CAPTURE", "MEMORY_NOT_CAPTURED"))
            self.assertIsNone(res_guard)

            # 2. Read across boundary (4 bytes in RW page, 4 bytes in PROT_NONE page)
            res_boundary, st_boundary = reader.read(guard_page - 4, 8)
            self.assertNotEqual(st_boundary, "COMPLETE")
            self.assertNotEqual(len(res_boundary or b""), 8, "Cannot return 8 full bytes for boundary read")

            # 3. Read unmapped address
            res_unmapped, st_unmapped = reader.read(0xdeadbeef000, 8)
            self.assertEqual(st_unmapped, "OUTSIDE_CAPTURE")
            self.assertIsNone(res_unmapped)
        finally:
            self._stop_target(proc)

    # -------------------------------------------------------------------------
    # S08 [P0] 증거 ID 및 출처 위조
    # -------------------------------------------------------------------------
    def test_S08_forged_evidence_id_and_provenance_rejection(self):
        """S08: Reject non-existent evidence IDs, irrelevant references, and contradictory observations."""
        proc, oracle = self._start_target()
        try:
            mgr = InvestigationManager(corpus_dir=self.corpus_dir)
            res = mgr.start_investigation(
                goal="S08 test",
                pid=proc.pid,
                debug_image=self.debug_bin,
                authorize_target=True,
            )
            self.assertIn(res.get("status"), ("COMPLETED", "IN_PROGRESS", "PARTIAL"))
            session = mgr.sessions[res["investigation_id"]]
            conv = ConversationalAnalysisService()

            # 1. Non-existent Evidence ID
            raw_fake = json.dumps({
                "summary": "Testing forged evidence",
                "evidence_refs": ["ev_non_existent_999999"],
                "observed_facts": [
                    {
                        "fact": "g_state.status is 1",
                        "field_path": "g_state.status",
                        "evidence_ids": ["ev_non_existent_999999"],
                    }
                ]
            })
            res_val, disarmed = conv.parse_and_validate_response(
                raw_fake,
                valid_evidence_ids=[ev.evidence_id for ev in session.ledger._records],
                session=session,
            )
            self.assertNotIn("ev_non_existent_999999", res_val["evidence_refs"])
            self.assertNotIn("ev_non_existent_999999", res_val["observed_facts"][0]["evidence_ids"])
            self.assertTrue(any("fabricated" in d.lower() or "stripped" in d.lower() for d in disarmed))

            # 2. Irrelevant Evidence ID
            identity_ev = next(ev for ev in session.ledger._records if ev.evidence_type == "RUNTIME_IDENTITY")
            raw_irrel = json.dumps({
                "summary": "State transition in status field",
                "evidence_refs": [identity_ev.evidence_id],
            })
            res_irrel, disarmed_irrel = conv.parse_and_validate_response(
                raw_irrel,
                valid_evidence_ids=[ev.evidence_id for ev in session.ledger._records],
                session=session,
            )
            self.assertNotIn(identity_ev.evidence_id, res_irrel["evidence_refs"])
            self.assertTrue(any("does not substantiate" in d.lower() or "unsupported" in d.lower() for d in disarmed_irrel))

            # 3. Contradictory Value
            claim_contra = {
                "fact": "g_state.status is 999",
                "field_path": "g_state.status",
                "observed_value": "999",
            }
            grounded_3, reason_3 = conv._is_fact_grounded(claim_contra, session=session, ledger=session.ledger)
            self.assertFalse(grounded_3)
            self.assertIn("contradicts", reason_3.lower())
        finally:
            self._stop_target(proc)

    # -------------------------------------------------------------------------
    # S09 [P1] Capture gap 및 시간 순서
    # -------------------------------------------------------------------------
    def test_S09_capture_gap_and_temporal_order(self):
        """S09: Preserve capture gaps and report UNCERTAINTY without fabricating intermediate data."""
        proc, oracle = self._start_target()
        try:
            watch_mgr = WatchSessionManager(corpus_dir=self.corpus_dir)
            sess = watch_mgr.create_session(pid=proc.pid, companion_elf_path=self.debug_bin, interval_ms=100)

            item = WatchItem(item_id="it_seq", name="g_state.sequence", scope="global", address=oracle["sequence"], size=4, type_name="uint32_t")
            sess.watch_items.append(item)

            # Observation 1 at seq=1
            obs1 = Observation(
                session_id=sess.session_id,
                seq=1,
                monotonic_ns=1_000_000_000,
                timestamp=datetime.now(timezone.utc).isoformat(),
                values={"it_seq": {"value": 100, "status": "OBSERVED"}},
                completeness="COMPLETE",
            )
            sess.observations.append(obs1)

            # Record a capture gap (interrupted window)
            gap = CaptureGap(
                gap_id="gap_test_01",
                start_ns=1_000_000_000,
                end_ns=1_500_000_000,
                duration_ms=500.0,
                reason="missed_sampling_window",
            )
            sess.gaps.append(gap)

            # Observation 2 at seq=5
            obs2 = Observation(
                session_id=sess.session_id,
                seq=5,
                monotonic_ns=1_500_000_000,
                timestamp=datetime.now(timezone.utc).isoformat(),
                values={"it_seq": {"value": 105, "status": "OBSERVED"}},
                completeness="COMPLETE",
            )
            sess.observations.append(obs2)
            sess.total_observations = 2

            watch_mgr._append_observation_to_file(sess.session_id, obs1)
            watch_mgr._append_observation_to_file(sess.session_id, obs2)
            watch_mgr._persist_session(sess)

            inv_mgr = InvestigationManager(corpus_dir=self.corpus_dir)
            inv_res = inv_mgr.start_investigation(
                goal="Analyze sequence mutations across observation window",
                watch_session_id=sess.session_id,
                authorize_target=True,
                watch_manager=watch_mgr,
            )
            self.assertIn(inv_res.get("status"), ("COMPLETED", "PARTIAL"))
            findings = inv_res.get("findings", [])

            # Ensure gap is explicitly recognized
            gap_findings = [f for f in findings if "gap" in f.get("title", "").lower()]
            self.assertGreaterEqual(len(gap_findings), 1)

            gf = gap_findings[0]
            self.assertEqual(gf.get("classification"), "UNKNOWN")
            self.assertIn("cannot be assumed unchanged", gf.get("description", ""))
            self.assertIsNotNone(gf.get("uncertainty"))
        finally:
            self._stop_target(proc)

    # -------------------------------------------------------------------------
    # S10 [P1] 포인터 및 객체 그래프 복원
    # -------------------------------------------------------------------------
    def test_S10_pointer_and_object_graph_restoration(self):
        """S10: Dereference g_state.active pointer and recursively reconstruct Buffer object and fields."""
        proc, oracle = self._start_target()
        try:
            backend = ProcessVmCaptureBackend()
            snap = backend.capture(pid=proc.pid)

            engine = OfflineSemanticEngine()
            state = engine.reconstruct(raw_snapshot=snap, debug_image=self.debug_bin)

            g_state_obj = next(o for o in state.objects if "g_state" in (o.get("primary_path") or ""))
            f_active = next(f for f in g_state_obj["fields"] if f["name"] == "active")

            # 1. Pointer field properties
            self.assertEqual(f_active["type"], "Buffer*")
            self.assertEqual(int(f_active["value"], 16), oracle["buffer"])
            self.assertEqual(f_active["status"], "RESOLVED")

            # 2. Pointed-to Buffer object
            target_ref_id = f_active.get("object_ref") or f_active.get("reference")
            self.assertIsNotNone(target_ref_id)

            target_obj = state.get_object(target_ref_id)
            self.assertIsNotNone(target_obj)
            self.assertEqual(target_obj["type"], "Buffer")
            self.assertEqual(target_obj["address"], oracle["buffer"])

            # 3. Buffer fields
            cap_f = next(f for f in target_obj["fields"] if f["name"] == "capacity")
            used_f = next(f for f in target_obj["fields"] if f["name"] == "used")
            data_f = next(f for f in target_obj["fields"] if f["name"] == "data")

            self.assertEqual(cap_f["value"], 64)
            self.assertEqual(used_f["value"], 10)
            self.assertEqual(data_f["value"][:25], [ord(c) for c in "AntigravityTestBufferData"])
        finally:
            self._stop_target(proc)

    # -------------------------------------------------------------------------
    # S11 [P1] PROT_NONE 가드 페이지 음성 대조군
    # -------------------------------------------------------------------------
    def test_S11_prot_none_guard_page_negative_control(self):
        """S11: Treat guard page proximity as static candidate without false causal promotion."""
        proc, oracle = self._start_target()
        try:
            guard_addr = oracle["guard"] + 4096

            mgr = InvestigationManager(corpus_dir=self.corpus_dir)
            res = mgr.start_investigation(
                goal=f"Check near_guard pointer proximity to guard 0x{guard_addr:x}",
                pid=proc.pid,
                debug_image=self.debug_bin,
                authorize_target=True,
                observation_window={"guard_address": guard_addr, "guard_threshold": 64},
            )
            self.assertIn(res.get("status"), ("COMPLETED", "IN_PROGRESS", "PARTIAL"))
            session = mgr.sessions[res["investigation_id"]]

            # Test that proximity to guard page NEVER promotes candidate to VALIDATED_CAUSAL_FUNCTION
            raw_json = json.dumps({
                "summary": "Near-guard pointer proximity observed",
                "hypotheses": [
                    {
                        "title": "Asserted Root Cause",
                        "claim": "access_near_guard_candidate() caused buffer overflow crash",
                        "status": "VALIDATED",
                        "function_candidates": [{
                            "function_name": "access_near_guard_candidate",
                            "candidate_tier": "VALIDATED_CAUSAL_FUNCTION",
                            "confirmed_root_cause": True,
                        }],
                    }
                ]
            })

            conv = ConversationalAnalysisService()
            res_conv, disarmed = conv.parse_and_validate_response(
                raw_json,
                valid_evidence_ids=[],
                session=session,
            )
            hypo = res_conv["hypotheses"][0]
            # Must be demoted to PROPOSED
            self.assertEqual(hypo["status"], "PROPOSED")
            cand = hypo["function_candidates"][0]
            # Candidate tier must be demoted to STATIC_CANDIDATE
            self.assertEqual(cand["candidate_tier"], "STATIC_CANDIDATE")
            self.assertFalse(cand["confirmed_root_cause"])

            report = QualityMetricsReport(
                scenarios_executed=1,
                scenarios_passed=1,
                unsupported_claims_attempted=1,
                unsupported_claims_rejected=1,
                invalid_evidence_attempted=1,
                invalid_evidence_rejected=1,
                unverified_candidates_evaluated=1,
                false_causal_promotions=0,
            )
            self.assertEqual(report.false_positive_causal_promotion_rate.value, 0.0)
        finally:
            self._stop_target(proc)

    # -------------------------------------------------------------------------
    # S12 [P1] 조사 결과까지 출처 추적
    # -------------------------------------------------------------------------
    def test_S12_traceability_to_investigation_results(self):
        """S12: Trace findings bidirectionally to EvidenceLedger records, memory byte ranges, and DWARF."""
        proc, oracle = self._start_target()
        try:
            mgr = InvestigationManager(corpus_dir=self.corpus_dir)
            res = mgr.start_investigation(
                goal="Full traceability verification for g_state",
                pid=proc.pid,
                debug_image=self.debug_bin,
                authorize_target=True,
            )
            self.assertIn(res.get("status"), ("COMPLETED", "IN_PROGRESS", "PARTIAL"))
            inv_id = res["investigation_id"]

            findings = mgr.sessions[inv_id].findings
            status_finding = next((f for f in findings if "status" in (f.c_type_path or "") or "status" in f.title.lower()), None)
            self.assertIsNotNone(status_finding, "Status finding must exist")

            drill_res = mgr.get_finding_drilldown(inv_id, status_finding.finding_id)
            self.assertTrue(drill_res.get("success"))
            drill = drill_res["drilldown"]

            # Trace from Finding to Evidence Ledger
            ev_records = drill.get("evidence_records", [])
            self.assertGreater(len(ev_records), 0)

            first_ev = ev_records[0]
            self.assertEqual(first_ev["evidence_id"], status_finding.evidence_ids[0])
            self.assertEqual(first_ev["nature"], "observation")

            ev_details = first_ev["details"]
            self.assertEqual(int(ev_details["address"], 16), oracle["status"])
            self.assertEqual(ev_details["value"], 1)

            # Trace to captured range
            captured_range = ev_details["provenance"]["captured_range"]
            range_start = int(captured_range[0], 16)
            range_end = int(captured_range[1], 16)
            self.assertEqual(range_start, oracle["status"])
            self.assertEqual(range_end - range_start, 4)

            # Trace to DWARF
            dwarf_info = ev_details["provenance"]["dwarf"]
            self.assertEqual(dwarf_info["member"], "status")
            self.assertEqual(dwarf_info["type"], "uint32_t")

            # Verify no hypothesis is falsified as OBSERVED_FACT
            for h in mgr.sessions[inv_id].hypotheses:
                self.assertNotEqual(getattr(h, "classification", ""), "OBSERVED_FACT")
        finally:
            self._stop_target(proc)


if __name__ == "__main__":
    unittest.main()
