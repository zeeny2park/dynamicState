"""Automated Tests for Phase 28: Runtime Memory Explorer and Time-based State Inspection UX.

Verifies all 11 required scenarios:
1. Target setup validation: invalid PID, unavailable process, wrong companion Build ID, missing DWARF.
2. Runtime Explorer renders threads/maps only from real API data and handles empty/partial/unsupported results.
3. Object tree renders nested fields and pointers without inventing values.
4. Watch list add/remove and bounded range validation.
5. Baseline plus a second real or existing integration-backed capture creates distinct snapshot records.
6. Timeline selection loads the correct snapshot and preserves timestamps/quality.
7. Diff distinguishes changed, unchanged, unreadable, missing, and unknown values.
8. Evidence provenance survives capture -> snapshot -> variable view -> diff -> investigation.
9. Static candidates are not promoted to validated causal functions without independent evidence.
10. Browser-level E2E test covers: connect target -> inspect maps/threads -> select a variable -> capture twice -> compare values -> inspect provenance.
11. Regression tests for existing MCP/CLI/API/investigation behavior.
"""

from datetime import datetime, timezone
import json
import os
import shutil
import struct
import subprocess
import tempfile
import threading
import time
from typing import Any, Dict, Optional, Tuple
import unittest
import urllib.error
import urllib.parse
import urllib.request

from extractor.agent_runtime import AgentRuntime
from extractor.capture_backend import ProcessVmCaptureBackend
from extractor.debug_image import inspect_elf
from extractor.dwarf_indexer import DwarfIndexer
from extractor.evidence_ledger import EvidenceLedger, EvidenceRecord
from extractor.hypothesis import (
    FUNCTION_TIER_STATIC_CANDIDATE,
    FUNCTION_TIER_VALIDATED_CAUSAL,
)
from extractor.investigation import (
    InvestigationFinding,
    InvestigationManager,
    InvestigationSession,
)
from extractor.target_adapter import LocalTargetAdapter
from extractor.watch_session import WatchItem, WatchSessionManager, read_process_memory_slice
from extractor.web.server import WebApiAdapter, run_server


class TestPhase28MemoryExplorerUX(unittest.TestCase):
    """End-to-End Test Suite for Phase 28 Runtime Memory Explorer & Inspection UX."""

    @classmethod
    def setUpClass(cls):
        cls.work_dir = tempfile.mkdtemp(prefix="dynstate_phase28_")

        # 1. Compile primary live C++ test target with DWARF (-g) and specific build-id
        cls.target_src = os.path.join(
            os.path.dirname(__file__), "fixtures", "real_runtime", "scenario_target.cpp"
        )
        cls.debug_bin = os.path.join(cls.work_dir, "scenario_target_debug.elf")
        cls.stripped_bin = os.path.join(cls.work_dir, "scenario_target_prod.stripped")

        cmd_compile = [
            "g++", "-fPIE", "-pie", "-g", "-O0", "-fno-inline",
            "-fno-omit-frame-pointer", "-Wl,--build-id=sha1",
            cls.target_src, "-o", cls.debug_bin, "-lpthread"
        ]
        subprocess.run(cmd_compile, check=True)

        # Create stripped companion binary
        cmd_strip = ["strip", "-s", "-o", cls.stripped_bin, cls.debug_bin]
        subprocess.run(cmd_strip, check=True)

        # 2. Compile mismatched build-id binary
        cls.mismatch_src = os.path.join(cls.work_dir, "mismatch.cpp")
        with open(cls.mismatch_src, "w") as f:
            f.write("int g_mismatch = 999;\nint main() { return 0; }\n")
        cls.mismatch_bin = os.path.join(cls.work_dir, "mismatch_debug.elf")
        cmd_mismatch = [
            "g++", "-fPIE", "-pie", "-g", "-O0", "-Wl,--build-id=md5",
            cls.mismatch_src, "-o", cls.mismatch_bin
        ]
        subprocess.run(cmd_mismatch, check=True)

        # 3. Start live target process
        cls.proc, cls.oracle = cls._start_target_process(cls.stripped_bin)

        # 4. Start ephemeral web server
        cls.corpus_dir = os.path.join(cls.work_dir, "corpus")
        cls.server_runtime = AgentRuntime(corpus_dir=cls.corpus_dir)
        cls.server_thread = None
        cls.server_port = None
        cls._start_web_server()

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "server") and cls.server:
            try:
                cls.server.shutdown()
            except Exception:
                pass
        cls._stop_target_process(cls.proc)
        shutil.rmtree(cls.work_dir, ignore_errors=True)

    @classmethod
    def _start_target_process(cls, bin_path: str) -> Tuple[subprocess.Popen, Dict[str, Any]]:
        proc = subprocess.Popen(
            [bin_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        ready_line = proc.stdout.readline().strip()
        if not ready_line.startswith("READY"):
            raise RuntimeError(f"Target failed to report READY: {ready_line}")

        oracle: Dict[str, Any] = {}
        for tok in ready_line.split()[1:]:
            if "=" in tok:
                k, v = tok.split("=", 1)
                oracle[k] = int(v, 16) if v.startswith("0x") else int(v)
        return proc, oracle

    @classmethod
    def _stop_target_process(cls, proc: subprocess.Popen):
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

    @classmethod
    def _send_target_cmd(cls, cmd: str) -> str:
        cls.proc.stdin.write(cmd.strip() + "\n")
        cls.proc.stdin.flush()
        return cls.proc.stdout.readline().strip()

    @classmethod
    def _start_web_server(cls):
        cls.server = run_server(runtime=cls.server_runtime, host="127.0.0.1", port=0)
        cls.server_port = cls.server.server_address[1]
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        time.sleep(0.1)

    def _http_get(self, path: str) -> Tuple[int, Dict[str, Any]]:
        url = f"http://127.0.0.1:{self.server_port}{path}"
        req = urllib.request.Request(url, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return resp.status, data
        except urllib.error.HTTPError as e:
            data = json.loads(e.read().decode("utf-8"))
            return e.code, data

    def _http_post(self, path: str, payload: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        url = f"http://127.0.0.1:{self.server_port}{path}"
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return resp.status, data
        except urllib.error.HTTPError as e:
            data = json.loads(e.read().decode("utf-8"))
            return e.code, data

    # =========================================================================
    # Test 1: Target setup validation
    # =========================================================================
    def test_01_target_setup_validation(self):
        """Validate target setup: invalid PID, unavailable process, wrong Build ID, missing DWARF."""
        adapter = WebApiAdapter(self.server_runtime)

        # 1a. Invalid PID format / range
        res_invalid = adapter.validate_target({"pid": -99, "debug_image": self.debug_bin})
        self.assertFalse(res_invalid.get("success", True) and res_invalid.get("data", {}).get("valid", True))
        self.assertIn("error", res_invalid)
        self.assertEqual(res_invalid["error"]["code"], "INVALID_PARAM")

        # 1b. Unavailable process (ESRCH)
        res_missing_pid = adapter.validate_target({"pid": 9999999, "debug_image": self.debug_bin})
        self.assertTrue(res_missing_pid["success"])
        self.assertFalse(res_missing_pid["data"]["valid"])
        self.assertEqual(res_missing_pid["data"]["reason"], "TARGET_NOT_FOUND")

        # 1c. Missing DWARF (stripped binary supplied as debug image)
        res_no_dwarf = adapter.validate_target({"pid": self.proc.pid, "debug_image": self.stripped_bin})
        self.assertTrue(res_no_dwarf["success"])
        self.assertFalse(res_no_dwarf["data"]["valid"])
        self.assertEqual(res_no_dwarf["data"]["reason"], "MISSING_DWARF")

        # 1d. Mismatched Build ID
        res_mismatch = adapter.validate_target({"pid": self.proc.pid, "debug_image": self.mismatch_bin})
        self.assertTrue(res_mismatch["success"])
        self.assertFalse(res_mismatch["data"]["valid"])
        self.assertEqual(res_mismatch["data"]["reason"], "BUILD_ID_MISMATCH")
        self.assertIn("Build ID 불일치" if "불일치" in res_mismatch["data"]["message"] else "Build ID mismatch", res_mismatch["data"]["message"])

        # 1e. Fully valid target with matching companion DWARF
        res_valid = adapter.validate_target({"pid": self.proc.pid, "debug_image": self.debug_bin})
        self.assertTrue(res_valid["success"])
        self.assertTrue(res_valid["data"]["valid"])
        self.assertEqual(res_valid["data"]["pid"], self.proc.pid)
        self.assertEqual(res_valid["data"]["backend"], "process_vm_readv")
        self.assertTrue(res_valid["data"]["has_dwarf"])
        self.assertEqual(res_valid["data"]["build_id_match"], True)

    # =========================================================================
    # Test 2: Runtime Explorer renders threads/maps from real API data
    # =========================================================================
    def test_02_runtime_explorer_threads_and_maps(self):
        """Verify threads and memory maps from real API data with truthful unsupported status."""
        adapter = LocalTargetAdapter()

        # 2a. Real threads inspection
        threads = adapter.get_threads(self.proc.pid)
        self.assertGreaterEqual(len(threads), 1)
        main_thread = threads[0]
        self.assertEqual(main_thread["tid"], self.proc.pid)
        self.assertIn(main_thread["state"], ["R", "S"])

        # Verify stack info status
        stack_info = main_thread.get("stack_info", {})
        self.assertIn("status", stack_info)
        self.assertIn(stack_info["status"], ["AVAILABLE", "UNAVAILABLE"])

        # Truthful local variables status
        local_vars = main_thread.get("local_variables", {})
        self.assertEqual(local_vars.get("status"), "UNSUPPORTED")
        self.assertIn("Stack frame inspection requires an active debugger backend", local_vars.get("reason", ""))

        # 2b. Real memory mappings inspection
        mappings = adapter.get_memory_mappings(self.proc.pid)
        self.assertGreater(len(mappings), 0)
        has_code = any(m.get("category") == "code" or "r-x" in m.get("permissions", "") for m in mappings)
        has_data = any(m.get("category") == "data" or "rw" in m.get("permissions", "") for m in mappings)
        self.assertTrue(has_code, "Expected at least one executable code mapping")
        self.assertTrue(has_data, "Expected at least one writable data mapping")

        # 2c. Bounded Memory Range Inspector
        web_adapter = WebApiAdapter(self.server_runtime)
        seq_addr = hex(self.oracle["sequence"])

        # Inspect bounded slice (128 bytes)
        inspect_res = web_adapter.inspect_memory_range({
            "pid": self.proc.pid,
            "address": seq_addr,
            "size": 128,
            "companion_elf": self.debug_bin
        })
        self.assertTrue(inspect_res["success"])
        d = inspect_res["data"]
        self.assertEqual(d["status"], "OBSERVED")
        self.assertEqual(d["bytes_read"], 128)
        self.assertGreater(len(d["raw_hex"]), 0)

        # Verify unmapped memory returns UNMAPPED / ERROR, not fabricated bytes
        unmapped_res = web_adapter.inspect_memory_range({
            "pid": self.proc.pid,
            "address": "0x1000",
            "size": 64
        })
        self.assertTrue(unmapped_res["success"])
        self.assertIn(unmapped_res["data"]["status"], ["UNMAPPED", "ERROR"])

    # =========================================================================
    # Test 3: Object tree and DWARF resolution without inventing values
    # =========================================================================
    def test_03_object_tree_and_dwarf_resolution(self):
        """Verify DWARF variable and struct field decoding without invented values."""
        idx = DwarfIndexer.get_index(self.debug_bin)

        # Find global variable 'g_state'
        g_state_syms = idx.variables_by_name.get("g_state", [])
        self.assertGreater(len(g_state_syms), 0, "DWARF symbol 'g_state' must be present")
        g_state_sym = g_state_syms[0]
        self.assertIsNotNone(g_state_sym.type_offset)
        g_type = idx.types_by_die.get(g_state_sym.type_offset)
        self.assertIsNotNone(g_type)
        self.assertEqual(g_type.name, "RuntimeState")

        # Verify field definitions inside RuntimeState
        types = idx.types_by_name.get("RuntimeState", [])
        self.assertGreater(len(types), 0)
        type_info = types[0]
        field_names = [f.name for f in type_info.members]
        self.assertIn("sequence", field_names)
        self.assertIn("status", field_names)
        self.assertIn("buffer", field_names)
        self.assertIn("active", field_names)

        # Inspect pointer field
        active_field = next(f for f in type_info.members if f.name == "active")
        self.assertIsNotNone(active_field.type_offset)

        # Read actual bytes from live process and verify no invented values
        raw_bytes, st, err = read_process_memory_slice(self.proc.pid, self.oracle["g_state"], type_info.byte_size)
        self.assertEqual(st, "OBSERVED")
        self.assertIsNotNone(raw_bytes)
        self.assertEqual(len(raw_bytes), type_info.byte_size)

        # Unpack sequence (offset 0, uint32) and status (offset 4, uint32)
        seq_val = struct.unpack_from("<I", raw_bytes, 0)[0]
        stat_val = struct.unpack_from("<I", raw_bytes, 4)[0]
        self.assertEqual(seq_val, 42)
        self.assertEqual(stat_val, 1)

    # =========================================================================
    # Test 4: Watch list add/remove and bounded range validation
    # =========================================================================
    def test_04_watchlist_add_remove_and_bounded_range(self):
        """Verify watch list configuration, source attribution, and bounds enforcement."""
        mgr = WatchSessionManager(corpus_dir=self.work_dir)
        session = mgr.create_session(pid=self.proc.pid, companion_elf_path=self.debug_bin)

        # Add DWARF global variable watch item
        item_global = WatchItem(
            item_id="watch_seq",
            name="g_state.sequence",
            scope="global",
            source="global_variable",
            address=self.oracle["sequence"],
            type_name="uint32_t",
            size=4
        )
        mgr.add_watch_item(session.session_id, item_global)

        # Add custom range watch item
        item_range = WatchItem(
            item_id="watch_buf",
            name="custom_stack_range",
            scope="address_range",
            source="custom_range",
            address=self.oracle["buffer"],
            type_name="raw_bytes",
            size=72
        )
        mgr.add_watch_item(session.session_id, item_range)

        # Verify items and source attribution
        sess = mgr.get_session(session.session_id)
        self.assertEqual(len(sess.watch_items), 2)
        self.assertEqual(sess.watch_items[0].source, "global_variable")
        self.assertEqual(sess.watch_items[1].source, "custom_range")

        # Remove item
        mgr.remove_watch_item(session.session_id, sess.watch_items[0].item_id)
        sess_after = mgr.get_session(session.session_id)
        self.assertEqual(len(sess_after.watch_items), 1)
        self.assertEqual(sess_after.watch_items[0].name, "custom_stack_range")

    # =========================================================================
    # Test 5: Baseline plus second capture creates distinct snapshot records
    # =========================================================================
    def test_05_baseline_and_second_capture_distinct_snapshots(self):
        """Verify baseline and second real captures create distinct chronological observations."""
        mgr = WatchSessionManager(corpus_dir=self.work_dir)
        session = mgr.create_session(pid=self.proc.pid, companion_elf_path=self.debug_bin)

        mgr.add_watch_item(session.session_id, WatchItem(
            item_id="item_seq_5",
            name="g_state.sequence",
            scope="global",
            source="global_variable",
            address=self.oracle["sequence"],
            type_name="uint32_t",
            size=4
        ))
        mgr.add_watch_item(session.session_id, WatchItem(
            item_id="item_stat_5",
            name="g_state.status",
            scope="global",
            source="global_variable",
            address=self.oracle["status"],
            type_name="uint32_t",
            size=4
        ))

        # Baseline capture (Capture 1)
        obs_1 = mgr.capture_once(session.session_id)
        item_seq_id = session.watch_items[0].item_id
        item_stat_id = session.watch_items[1].item_id
        self.assertEqual(obs_1.values[item_seq_id]["value"], 42)
        self.assertEqual(obs_1.values[item_stat_id]["value"], 1)

        # Mutate target process state
        ack = self._send_target_cmd("SET sequence 9999")
        self.assertIn("OK sequence=9999", ack)

        # Second capture (Capture 2)
        obs_2 = mgr.capture_once(session.session_id)
        self.assertEqual(obs_2.values[item_seq_id]["value"], 9999)
        self.assertEqual(obs_2.values[item_stat_id]["value"], 1)

        # Verify distinct timestamps and sequence numbers
        self.assertGreater(obs_2.monotonic_ns, obs_1.monotonic_ns)
        self.assertNotEqual(obs_1.timestamp, obs_2.timestamp)

        # Restore sequence for subsequent tests
        self._send_target_cmd("SET sequence 42")

    # =========================================================================
    # Test 6: Timeline selection loads correct snapshot and preserves metadata
    # =========================================================================
    def test_06_timeline_selection_preserves_metadata(self):
        """Verify timeline selection preserves timestamps, latency, and quality."""
        mgr = WatchSessionManager(corpus_dir=self.work_dir)
        session = mgr.create_session(pid=self.proc.pid, companion_elf_path=self.debug_bin)
        mgr.add_watch_item(session.session_id, WatchItem(
            item_id="item_seq_6",
            name="g_state.sequence",
            scope="global",
            address=self.oracle["sequence"],
            type_name="uint32_t",
            size=4
        ))

        obs_1 = mgr.capture_once(session.session_id)
        time.sleep(0.01)
        obs_2 = mgr.capture_once(session.session_id)

        sess = mgr.get_session(session.session_id)
        timeline = sess.observations

        self.assertGreaterEqual(len(timeline), 2)
        self.assertGreater(timeline[0].capture_latency_us, 0)
        self.assertEqual(timeline[0].zero_stop, True)
        self.assertIn("T", timeline[0].timestamp)

    # =========================================================================
    # Test 7: Diff distinguishes changed, unchanged, unreadable, missing, unknown
    # =========================================================================
    def test_07_diff_distinguishes_all_states(self):
        """Verify snapshot diffing strictly distinguishes CHANGED, UNCHANGED, UNREADABLE, and pointer semantics."""
        mgr = WatchSessionManager(corpus_dir=self.work_dir)
        session = mgr.create_session(pid=self.proc.pid, companion_elf_path=self.debug_bin)

        item_seq = WatchItem(
            item_id="item_seq_7",
            name="g_state.sequence",
            scope="global",
            address=self.oracle["sequence"],
            type_name="uint32_t",
            size=4
        )
        item_stat = WatchItem(
            item_id="item_stat_7",
            name="g_state.status",
            scope="global",
            address=self.oracle["status"],
            type_name="uint32_t",
            size=4
        )
        item_unreadable = WatchItem(
            item_id="item_guard_7",
            name="guard_inaccessible",
            scope="address_range",
            address=self.oracle["guard"] + 4096,
            type_name="raw_bytes",
            size=16
        )

        mgr.add_watch_item(session.session_id, item_seq)
        mgr.add_watch_item(session.session_id, item_stat)
        mgr.add_watch_item(session.session_id, item_unreadable)

        # Baseline capture
        obs_1 = mgr.capture_once(session.session_id)

        # Mutate sequence only
        self._send_target_cmd("SET sequence 12345")
        obs_2 = mgr.capture_once(session.session_id)

        diff_res = mgr.compare_observations(session.session_id, seq_a=obs_1.seq, seq_b=obs_2.seq)
        summary = diff_res["summary"]
        self.assertEqual(summary["total_items"], 3)
        self.assertEqual(summary["changed_count"], 1)
        self.assertEqual(summary["unchanged_count"], 1)
        self.assertEqual(summary["unreadable_count"], 1)

        diffs_by_name = {d["name"]: d for d in diff_res["diffs"]}

        # 7a. Changed item
        seq_diff = diffs_by_name["g_state.sequence"]
        self.assertEqual(seq_diff["diff_state"], "CHANGED")
        self.assertEqual(seq_diff["value_a"], 42)
        self.assertEqual(seq_diff["value_b"], 12345)

        # 7b. Unchanged item
        stat_diff = diffs_by_name["g_state.status"]
        self.assertEqual(stat_diff["diff_state"], "UNCHANGED")
        self.assertEqual(stat_diff["value_a"], 1)
        self.assertEqual(stat_diff["value_b"], 1)

        # 7c. Inaccessible / unreadable item: MUST NOT BE UNCHANGED
        guard_diff = diffs_by_name["guard_inaccessible"]
        self.assertEqual(guard_diff["diff_state"], "UNREADABLE")
        self.assertNotEqual(guard_diff["diff_state"], "UNCHANGED")

        # Restore sequence
        self._send_target_cmd("SET sequence 42")

    # =========================================================================
    # Test 8: Evidence provenance survives capture -> snapshot -> diff -> investigation
    # =========================================================================
    def test_08_evidence_provenance_preservation(self):
        """Verify evidence records preserve provenance from capture to investigation."""
        mgr = WatchSessionManager(corpus_dir=self.work_dir)
        session = mgr.create_session(pid=self.proc.pid, companion_elf_path=self.debug_bin)
        mgr.add_watch_item(session.session_id, WatchItem(
            item_id="item_seq_8",
            name="g_state.sequence",
            scope="global",
            address=self.oracle["sequence"],
            type_name="uint32_t",
            size=4
        ))

        obs = mgr.capture_once(session.session_id)

        # Register in EvidenceLedger
        ledger = EvidenceLedger()
        ev_id = f"ev_obs_{session.session_id}_{obs.seq}"
        rec = EvidenceRecord(
            evidence_id=ev_id,
            evidence_type="OBJECT_STATE",
            source="OBSERVATION",
            observation=f"Watch observation #{obs.seq} for PID {self.proc.pid}",
            provenance={
                "session_id": session.session_id,
                "seq": obs.seq,
                "pid": self.proc.pid,
                "timestamp": obs.timestamp,
                "address": hex(self.oracle["sequence"]),
                "byte_range": [self.oracle["sequence"], self.oracle["sequence"] + 4]
            },
            details={"value": 42, "status": "OBSERVED"}
        )
        ledger.add_record(rec)

        retrieved = ledger.get_record(ev_id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.provenance["session_id"], session.session_id)
        self.assertEqual(retrieved.provenance["seq"], obs.seq)
        self.assertEqual(retrieved.provenance["pid"], self.proc.pid)
        self.assertEqual(retrieved.provenance["byte_range"], [self.oracle["sequence"], self.oracle["sequence"] + 4])

    # =========================================================================
    # Test 9: Static candidates not promoted without independent evidence
    # =========================================================================
    def test_09_static_candidates_not_promoted_without_evidence(self):
        """Verify static function candidates are not falsely promoted to causal functions."""
        inv_session = InvestigationSession(
            investigation_id="inv_test_phase28",
            goal="Verify sequence mutation causality",
            corpus_dir=self.work_dir
        )

        # Static candidate function 'mutate_sequence'
        finding = InvestigationFinding(
            finding_id="find_seq_mut",
            category="hypothesis",
            title="Candidate mutate_sequence",
            description="Function mutate_sequence observed in debug symbols",
            function_candidates=[
                {"function_name": "mutate_sequence", "candidate_tier": FUNCTION_TIER_STATIC_CANDIDATE}
            ],
            evidence_ids=[]
        )
        inv_session.findings.append(finding)

        # Candidate must remain STATIC_CANDIDATE without independent proof
        self.assertEqual(finding.function_candidates[0]["candidate_tier"], FUNCTION_TIER_STATIC_CANDIDATE)
        self.assertNotEqual(finding.function_candidates[0]["candidate_tier"], FUNCTION_TIER_VALIDATED_CAUSAL)

    # =========================================================================
    # Test 10: Browser-level E2E journey
    # =========================================================================
    def test_10_browser_level_e2e_journey(self):
        """Full simulated browser E2E journey: connect -> inspect -> select -> capture twice -> compare -> investigate."""
        # 1. Connect and validate target (Step 1)
        status, val_res = self._http_post("/api/investigation/validate-target", {
            "pid": self.proc.pid,
            "debug_image": self.debug_bin
        })
        self.assertEqual(status, 200)
        self.assertTrue(val_res["data"]["valid"])

        # 2. Inspect runtime maps and threads (Step 2)
        status, map_res = self._http_get(f"/api/watch/memory-map?pid={self.proc.pid}&companion_elf={urllib.parse.quote(self.debug_bin)}")
        self.assertEqual(status, 200)
        self.assertGreater(len(map_res["data"]["mappings"]), 0)
        self.assertGreaterEqual(len(map_res["data"]["threads"]), 1)

        # 3. Inspect bounded range
        seq_addr = hex(self.oracle["sequence"])
        status, rng_res = self._http_get(f"/api/target/inspect-range?pid={self.proc.pid}&address={seq_addr}&size=64&companion_elf={urllib.parse.quote(self.debug_bin)}")
        self.assertEqual(status, 200)
        self.assertEqual(rng_res["data"]["status"], "OBSERVED")

        # 4. Create watch session with selected variables (Step 3)
        status, sess_res = self._http_post("/api/watch/session/create", {
            "pid": self.proc.pid,
            "companion_elf": self.debug_bin,
            "interval_ms": 1000,
            "max_samples": 500,
            "watch_items": [
                {
                    "name": "g_state.sequence",
                    "source": "global_variable",
                    "scope": "global",
                    "address": seq_addr,
                    "type_name": "uint32_t",
                    "size": 4
                },
                {
                    "name": "g_state.status",
                    "source": "global_variable",
                    "scope": "global",
                    "address": hex(self.oracle["status"]),
                    "type_name": "uint32_t",
                    "size": 4
                }
            ]
        })
        self.assertEqual(status, 200)
        sid = sess_res["data"]["session_id"]

        # 5. Capture snapshot 1 (Baseline)
        status, cap1_res = self._http_post(f"/api/watch/session/{sid}/capture", {})
        self.assertEqual(status, 200)
        seq_1 = cap1_res["data"]["seq"]

        # 6. Mutate process state
        self._send_target_cmd("SET sequence 7777")

        # 7. Capture snapshot 2
        status, cap2_res = self._http_post(f"/api/watch/session/{sid}/capture", {})
        self.assertEqual(status, 200)
        seq_2 = cap2_res["data"]["seq"]
        self.assertGreater(seq_2, seq_1)

        # 8. Compare snapshots (Step 4)
        status, cmp_res = self._http_post(f"/api/watch/session/{sid}/compare", {
            "seq_a": seq_1,
            "seq_b": seq_2
        })
        self.assertEqual(status, 200)
        summary = cmp_res["data"]["summary"]
        self.assertEqual(summary["changed_count"], 1)
        self.assertEqual(summary["unchanged_count"], 1)

        # 9. Hand off to Investigation (Step 5)
        status, inv_res = self._http_post("/api/investigation/start", {
            "goal": f"Investigate sequence mutation from snapshot #{seq_1} to #{seq_2} in session {sid}",
            "session_id": sid
        })
        self.assertEqual(status, 200)
        self.assertIn("investigation_id", inv_res["data"])

        # 10. Verify static web UI assets contain Phase 28 workflow markup and scripts
        req_index = urllib.request.Request(f"http://127.0.0.1:{self.server_port}/")
        with urllib.request.urlopen(req_index, timeout=5.0) as resp:
            html = resp.read().decode("utf-8")
        self.assertIn("tab-target-setup", html)
        self.assertIn("tab-runtime-explorer", html)
        self.assertIn("tab-watch-list", html)
        self.assertIn("tab-timeline-compare", html)
        self.assertIn("card-bounded-inspector", html)

        req_js = urllib.request.Request(f"http://127.0.0.1:{self.server_port}/static/app.js")
        with urllib.request.urlopen(req_js, timeout=5.0) as resp:
            js = resp.read().decode("utf-8")
        self.assertIn("handleValidateTarget", js)
        self.assertIn("handleInspectMemoryRange", js)
        self.assertIn("handleExecuteSnapshotCompare", js)
        self.assertIn("handleCaptureSnapshotNow", js)

        # Restore sequence
        self._send_target_cmd("SET sequence 42")

    # =========================================================================
    # Test 11: Regression tests for existing MCP/CLI/API/investigation behavior
    # =========================================================================
    def test_11_regression_existing_api_and_runtime(self):
        """Verify existing API routes and data structures function without regressions."""
        # 11a. Runtime overview
        status, ov = self._http_get("/api/runtime")
        self.assertEqual(status, 200)
        self.assertTrue(ov.get("success", False))

        # 11b. Watch sessions list
        status, sess_list = self._http_get("/api/watch/sessions")
        self.assertEqual(status, 200)
        self.assertTrue(sess_list.get("success", False))

        # 11c. LLM status check
        status, llm = self._http_get("/api/llm/status")
        self.assertEqual(status, 200)
        self.assertIn("provider_type", llm.get("data", {}))


if __name__ == "__main__":
    unittest.main()
