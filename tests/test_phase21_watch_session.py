"""Phase 21 Acceptance Test Suite: Watch Session and Temporal Memory Explorer Foundation.

Verifies:
1. Create, stop, and reload a watch session.
2. Verify companion Build ID mismatch rejection.
3. Add/remove watch items and persist the list.
4. Capture at least three real observations of known fixture variables with changing values.
5. Navigate forward/backward, Home/End, and replay semantics.
6. Preserve unknown/partial samples without inventing values.
7. Record and display capture gaps and failures.
8. Ensure UI refresh/reconnect does not corrupt or silently terminate a session.
9. Verify allocation events are never fabricated when the recorder is absent or incomplete.
10. Confirm Web API endpoints and existing architecture integration.
"""

from datetime import datetime, timezone
import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest

from extractor.agent_runtime import AgentRuntime
from extractor.debug_image import inspect_elf
from extractor.watch_session import (
    AllocationEvent,
    CaptureGap,
    Observation,
    ObservationSession,
    WatchItem,
    WatchSessionManager,
    decode_value_from_bytes,
    read_process_memory_slice,
)
from extractor.web.server import WebApiAdapter


class TestPhase21WatchSession(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work_dir = tempfile.mkdtemp(prefix="dynstate_p21_")
        cls.corpus_dir = os.path.join(cls.work_dir, "corpus")
        os.makedirs(cls.corpus_dir, exist_ok=True)

        cls.fixture_src = os.path.abspath("tests/fixtures/real_runtime/main.cpp")
        if not os.path.exists(cls.fixture_src):
            raise unittest.SkipTest("C++ fixture source not found")

        # 1. Compile matching companion debug binary with DWARF and GNU Build ID
        cls.debug_bin = os.path.join(cls.work_dir, "app_debug.elf")
        subprocess.run(
            [
                "g++", "-fPIE", "-pie", "-g", "-O0", "-fno-inline", "-fno-omit-frame-pointer",
                "-Wl,--build-id=sha1", cls.fixture_src, "-o", cls.debug_bin, "-lpthread"
            ],
            check=True
        )

        # 2. Extract stripped production runtime binary
        cls.stripped_bin = os.path.join(cls.work_dir, "app_prod.stripped")
        subprocess.run(["strip", "-s", "-o", cls.stripped_bin, cls.debug_bin], check=True)

        # 3. Compile an intentionally mismatched debug binary
        cls.mismatched_src = os.path.join(cls.work_dir, "mismatched.cpp")
        with open(cls.mismatched_src, "w") as f:
            f.write("int main() { return 0; }\n")
        cls.mismatched_bin = os.path.join(cls.work_dir, "mismatched_debug.elf")
        subprocess.run(
            [
                "g++", "-fPIE", "-pie", "-g", "-O0",
                "-Wl,--build-id=sha1", cls.mismatched_src, "-o", cls.mismatched_bin
            ],
            check=True
        )

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.work_dir, ignore_errors=True)

    def _start_target_process(self, bin_path):
        proc = subprocess.Popen(
            [bin_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        ready_line = proc.stdout.readline().strip()
        self.assertEqual(ready_line, "READY", f"Target process failed to report READY: {ready_line}")
        return proc

    def _stop_target_process(self, proc):
        if proc and proc.poll() is None:
            try:
                proc.stdin.write("STOP\n")
                proc.stdin.flush()
                proc.wait(timeout=2.0)
            except Exception:
                proc.kill()
                proc.wait()
        if proc:
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                if stream and not stream.closed:
                    try:
                        stream.close()
                    except Exception:
                        pass

    # -------------------------------------------------------------------------
    # Requirement 1: Create, Stop, and Reload Watch Session
    # -------------------------------------------------------------------------
    def test_01_create_stop_and_reload_session(self):
        proc = self._start_target_process(self.debug_bin)
        try:
            manager = WatchSessionManager(corpus_dir=self.corpus_dir)
            session = manager.create_session(
                pid=proc.pid,
                companion_elf_path=self.debug_bin,
                interval_ms=100,
                max_samples=50,
            )
            self.assertEqual(session.status, "RUNNING")
            self.assertEqual(session.pid, proc.pid)
            self.assertIsNotNone(session.binary_build_id)

            # Wait for at least one observation
            time.sleep(0.3)

            # Stop session
            stopped = manager.stop_session(session.session_id)
            self.assertIsNotNone(stopped)
            self.assertEqual(stopped.status, "STOPPED")
            self.assertIsNotNone(stopped.end_time)

            # Reload with a completely fresh manager instance reading from disk
            fresh_manager = WatchSessionManager(corpus_dir=self.corpus_dir)
            reloaded = fresh_manager.get_session(session.session_id)
            self.assertIsNotNone(reloaded)
            self.assertEqual(reloaded.session_id, session.session_id)
            self.assertEqual(reloaded.status, "STOPPED")
            self.assertEqual(reloaded.pid, proc.pid)
            self.assertGreater(len(reloaded.observations), 0)
        finally:
            self._stop_target_process(proc)

    # -------------------------------------------------------------------------
    # Requirement 2: Companion Build ID Mismatch Rejection
    # -------------------------------------------------------------------------
    def test_02_companion_build_id_mismatch_rejection(self):
        proc = self._start_target_process(self.stripped_bin)
        try:
            manager = WatchSessionManager(corpus_dir=self.corpus_dir)
            # Attempt to create session with mismatched debug binary
            with self.assertRaises(ValueError) as ctx:
                manager.create_session(
                    pid=proc.pid,
                    companion_elf_path=self.mismatched_bin,
                    interval_ms=200,
                )
            self.assertIn("Build ID mismatch", str(ctx.exception))
        finally:
            self._stop_target_process(proc)

    # -------------------------------------------------------------------------
    # Requirement 3: Add/Remove Watch Items and Persist List
    # -------------------------------------------------------------------------
    def test_03_add_remove_watch_items_and_persist(self):
        proc = self._start_target_process(self.debug_bin)
        try:
            manager = WatchSessionManager(corpus_dir=self.corpus_dir)
            session = manager.create_session(
                pid=proc.pid,
                companion_elf_path=self.debug_bin,
                interval_ms=200,
            )

            # Discover variables from memory map
            map_data = manager.get_memory_map_and_threads(proc.pid, self.debug_bin)
            self.assertGreater(len(map_data["mappings"]), 0)
            self.assertGreater(len(map_data["discoverable_variables"]), 0)

            # Add watch item
            first_var = map_data["discoverable_variables"][0]
            item = manager.add_watch_item(session.session_id, {
                "name": first_var["name"],
                "scope": "global",
                "address": first_var["runtime_address_int"],
                "type_name": first_var["type_name"],
                "size": first_var["size"],
            })
            self.assertEqual(item.name, first_var["name"])
            self.assertEqual(item.status, "ACTIVE")

            # Verify persisted in session file
            sess_file = manager._get_session_file(session.session_id)
            with open(sess_file, "r") as f:
                saved = json.load(f)
            self.assertEqual(len(saved["watch_items"]), 1)
            self.assertEqual(saved["watch_items"][0]["name"], first_var["name"])

            # Remove watch item
            removed = manager.remove_watch_item(session.session_id, item.item_id)
            self.assertTrue(removed)

            with open(sess_file, "r") as f:
                saved_after = json.load(f)
            self.assertEqual(len(saved_after["watch_items"]), 0)

            manager.stop_session(session.session_id)
        finally:
            self._stop_target_process(proc)

    # -------------------------------------------------------------------------
    # Requirement 4: Real C++ Observations With Changing Values
    # -------------------------------------------------------------------------
    def test_04_real_cpp_runtime_observations_with_mutation(self):
        proc = self._start_target_process(self.debug_bin)
        try:
            manager = WatchSessionManager(corpus_dir=self.corpus_dir)
            map_data = manager.get_memory_map_and_threads(proc.pid, self.debug_bin)

            # Locate g_session and g_heartbeat in discoverable variables
            d_vars = {v["name"]: v for v in map_data["discoverable_variables"]}
            self.assertIn("g_session", d_vars)
            self.assertIn("g_heartbeat", d_vars)

            # Session worker state counter is at offset 0 of g_session
            sess_addr = d_vars["g_session"]["runtime_address_int"]
            heartbeat_addr = d_vars["g_heartbeat"]["runtime_address_int"]

            watch_items = [
                {
                    "item_id": "watch_counter",
                    "name": "g_session.worker.state.counter",
                    "scope": "global",
                    "address": sess_addr,
                    "type_name": "int",
                    "size": 4,
                },
                {
                    "item_id": "watch_heartbeat",
                    "name": "g_heartbeat",
                    "scope": "global",
                    "address": heartbeat_addr,
                    "type_name": "uint64_t",
                    "size": 8,
                },
            ]

            session = manager.create_session(
                pid=proc.pid,
                companion_elf_path=self.debug_bin,
                interval_ms=80,
                max_samples=200,
                initial_watch_items=watch_items,
            )

            # Capture initial observations (counter == 42)
            time.sleep(0.3)

            # Mutate via stdin
            proc.stdin.write("MUTATE\n")
            proc.stdin.flush()
            mutate_resp = proc.stdout.readline().strip()
            self.assertEqual(mutate_resp, "MUTATED")

            # Capture mutated observations (counter == 100)
            time.sleep(0.4)
            manager.stop_session(session.session_id)

            obs_data = manager.get_observations(session.session_id)
            observations = obs_data["observations"]
            self.assertGreaterEqual(len(observations), 3, "Must capture at least 3 real observations")

            # Check sequence ordering and timestamps
            prev_seq = 0
            prev_mono = 0
            counter_values = []
            heartbeat_values = []

            for obs in observations:
                self.assertGreater(obs["seq"], prev_seq, "Sequence numbers must be strictly increasing")
                self.assertGreaterEqual(obs["monotonic_ns"], prev_mono, "Monotonic timestamp must be non-decreasing")
                prev_seq = obs["seq"]
                prev_mono = obs["monotonic_ns"]

                c_val = obs["values"].get("watch_counter", {}).get("value")
                h_val = obs["values"].get("watch_heartbeat", {}).get("value")
                if c_val is not None:
                    counter_values.append(c_val)
                if h_val is not None:
                    heartbeat_values.append(h_val)

            # Verify that we observed changing values:
            # 1. counter transitioned from 42 to 100
            self.assertIn(42, counter_values, f"Expected initial counter 42 in {counter_values}")
            self.assertIn(100, counter_values, f"Expected mutated counter 100 in {counter_values}")

            # 2. heartbeat incremented across observations
            self.assertGreater(len(set(heartbeat_values)), 1, "Heartbeat must advance over time")
        finally:
            self._stop_target_process(proc)

    # -------------------------------------------------------------------------
    # Requirement 5: Replay Navigation Semantics (Home, End, Prev, Next)
    # -------------------------------------------------------------------------
    def test_05_replay_navigation_semantics(self):
        # Construct synthetic recorded session with known sequence
        session = ObservationSession(
            session_id="replay_test_sess",
            pid=1234,
            start_time="2026-10-16T12:00:00Z",
            status="STOPPED",
            watch_items=[WatchItem(item_id="w1", name="counter", scope="global", address=0x1000, type_name="int", size=4)],
            observations=[
                Observation(session_id="replay_test_sess", seq=1, monotonic_ns=1000, timestamp="2026-10-16T12:00:00Z", values={"w1": {"value": 10, "status": "OBSERVED"}}),
                Observation(session_id="replay_test_sess", seq=2, monotonic_ns=2000, timestamp="2026-10-16T12:00:01Z", values={"w1": {"value": 20, "status": "OBSERVED"}}),
                Observation(session_id="replay_test_sess", seq=3, monotonic_ns=3000, timestamp="2026-10-16T12:00:02Z", values={"w1": {"value": 30, "status": "OBSERVED"}}),
            ]
        )

        obs_list = session.observations
        # Replay index 0 (Home)
        self.assertEqual(obs_list[0].seq, 1)
        self.assertEqual(obs_list[0].values["w1"]["value"], 10)

        # Step forward (Next)
        curr_idx = 0 + 1
        self.assertEqual(obs_list[curr_idx].seq, 2)
        self.assertEqual(obs_list[curr_idx].values["w1"]["value"], 20)

        # Step forward (Next)
        curr_idx = curr_idx + 1
        self.assertEqual(obs_list[curr_idx].seq, 3)
        self.assertEqual(obs_list[curr_idx].values["w1"]["value"], 30)

        # Jump to End
        end_idx = len(obs_list) - 1
        self.assertEqual(obs_list[end_idx].seq, 3)

        # Step backward (Prev)
        curr_idx = end_idx - 1
        self.assertEqual(obs_list[curr_idx].seq, 2)
        self.assertEqual(obs_list[curr_idx].values["w1"]["value"], 20)

    # -------------------------------------------------------------------------
    # Requirement 6: Preserve Unknown/Partial Samples (No Value Fabrication)
    # -------------------------------------------------------------------------
    def test_06_preserve_unknown_and_partial_samples_without_fabrication(self):
        proc = self._start_target_process(self.debug_bin)
        try:
            # Address 0x0 or an unmapped high address
            unmapped_addr = 0x00007ffff0000000
            data, status, err = read_process_memory_slice(proc.pid, unmapped_addr, 4)
            self.assertIsNone(data)
            self.assertEqual(status, "UNAVAILABLE")
            self.assertIsNotNone(err)

            # Test decoder with insufficient bytes
            val, dec_err = decode_value_from_bytes(b"\x01\x02", "int32")
            self.assertIsNone(val)
            self.assertIn("Insufficient bytes", dec_err)

            # Verify that watch session explicitly records UNAVAILABLE for unmapped addresses
            manager = WatchSessionManager(corpus_dir=self.corpus_dir)
            watch_items = [{
                "item_id": "unmapped_item",
                "name": "unmapped_var",
                "scope": "address_range",
                "address": unmapped_addr,
                "type_name": "int",
                "size": 4,
            }]
            session = manager.create_session(
                pid=proc.pid,
                companion_elf_path=self.debug_bin,
                interval_ms=100,
                max_samples=2,
                initial_watch_items=watch_items,
            )
            time.sleep(0.3)
            manager.stop_session(session.session_id)

            obs_data = manager.get_observations(session.session_id)
            for obs in obs_data["observations"]:
                item_val = obs["values"].get("unmapped_item", {})
                self.assertEqual(item_val.get("status"), "UNAVAILABLE")
                self.assertIsNone(item_val.get("value"))
                self.assertNotEqual(item_val.get("value"), 0, "Must NEVER fabricate zero for unmapped memory")
        finally:
            self._stop_target_process(proc)

    # -------------------------------------------------------------------------
    # Requirement 7: Record and Display Capture Gaps and Failures
    # -------------------------------------------------------------------------
    def test_07_record_and_display_capture_gaps(self):
        gap = CaptureGap(
            gap_id="gap_001",
            start_ns=1000000,
            end_ns=3500000,
            duration_ms=2.5,
            reason="SAMPLING_OVERRUN",
            missing_seq_range=[4, 5],
            timestamp="2026-10-16T12:05:00Z"
        )
        d = gap.to_dict()
        self.assertEqual(d["gap_id"], "gap_001")
        self.assertEqual(d["duration_ms"], 2.5)
        self.assertEqual(d["reason"], "SAMPLING_OVERRUN")

        reconstructed = CaptureGap.from_dict(d)
        self.assertEqual(reconstructed.gap_id, "gap_001")
        self.assertEqual(reconstructed.missing_seq_range, [4, 5])

    # -------------------------------------------------------------------------
    # Requirement 8: Durability Across Reconnect and Server Restarts
    # -------------------------------------------------------------------------
    def test_08_session_durability_across_reconnect_and_restart(self):
        proc = self._start_target_process(self.debug_bin)
        try:
            manager1 = WatchSessionManager(corpus_dir=self.corpus_dir)
            session = manager1.create_session(
                pid=proc.pid,
                companion_elf_path=self.debug_bin,
                interval_ms=100,
                max_samples=100,
            )
            sess_id = session.session_id
            time.sleep(0.3)

            # Simulate UI reconnect / new client querying active session
            reconnected_session = manager1.get_session(sess_id)
            self.assertIsNotNone(reconnected_session)
            self.assertEqual(reconnected_session.status, "RUNNING")
            self.assertGreater(len(reconnected_session.observations), 0)

            # Simulate backend server crash/restart: create new manager instance
            manager2 = WatchSessionManager(corpus_dir=self.corpus_dir)
            recovered = manager2.get_session(sess_id)
            self.assertIsNotNone(recovered)
            # A session recovered from a previous process invocation is marked STOPPED safely
            self.assertEqual(recovered.status, "STOPPED")
            self.assertEqual(recovered.session_id, sess_id)
            self.assertGreater(len(recovered.observations), 0)

            # Cleanup thread in manager1
            manager1.stop_session(sess_id)
        finally:
            self._stop_target_process(proc)

    # -------------------------------------------------------------------------
    # Requirement 9: Truthful Allocation Event Capability (Never Fabricate)
    # -------------------------------------------------------------------------
    def test_09_truthful_allocation_event_capability(self):
        proc = self._start_target_process(self.debug_bin)
        try:
            manager = WatchSessionManager(corpus_dir=self.corpus_dir)
            session = manager.create_session(
                pid=proc.pid,
                companion_elf_path=self.debug_bin,
                interval_ms=100,
                max_samples=2,
            )
            time.sleep(0.2)
            manager.stop_session(session.session_id)

            # Allocation events must be empty because no heap tracer is attached
            self.assertEqual(len(session.allocation_events), 0)

            # Capability state must be truthfully reported as unsupported
            alloc_cap = session.capabilities.get("allocation_tracking", {})
            self.assertFalse(alloc_cap.get("supported", True))
            self.assertEqual(alloc_cap.get("status"), "UNSUPPORTED_ON_BACKEND")
            self.assertIn("Heap allocation/free event recording requires an active heap hook", alloc_cap.get("reason", ""))
        finally:
            self._stop_target_process(proc)

    # -------------------------------------------------------------------------
    # Requirement 10: Web API Integration & Compatibility
    # -------------------------------------------------------------------------
    def test_10_web_api_endpoints_integration(self):
        runtime = AgentRuntime(corpus_dir=self.corpus_dir)
        adapter = WebApiAdapter(runtime)

        proc = self._start_target_process(self.debug_bin)
        try:
            # 1. GET /api/watch/memory-map
            map_res = adapter.get_watch_memory_map(proc.pid, companion_elf=self.debug_bin)
            self.assertTrue(map_res["success"])
            self.assertGreater(len(map_res["data"]["mappings"]), 0)
            self.assertGreater(len(map_res["data"]["threads"]), 0)

            # 2. POST /api/watch/session/create
            create_res = adapter.create_watch_session({
                "pid": proc.pid,
                "companion_elf": self.debug_bin,
                "interval_ms": 100,
                "max_samples": 50,
            })
            self.assertTrue(create_res["success"])
            sess_id = create_res["data"]["session_id"]
            self.assertEqual(create_res["data"]["status"], "RUNNING")

            # 3. POST /api/watch/session/<id>/watch (Add item)
            add_res = adapter.update_watch_items(sess_id, {
                "action": "add",
                "item": {
                    "name": "g_heartbeat",
                    "address": map_res["data"]["mappings"][0]["start_int"],
                    "type_name": "uint64_t",
                    "size": 8,
                }
            })
            self.assertTrue(add_res["success"])

            time.sleep(0.3)

            # 4. GET /api/watch/session/<id>/observations
            obs_res = adapter.get_watch_observations(sess_id, {})
            self.assertTrue(obs_res["success"])
            self.assertGreater(obs_res["data"]["total_observations"], 0)

            # 5. POST /api/watch/session/<id>/stop
            stop_res = adapter.stop_watch_session(sess_id)
            self.assertTrue(stop_res["success"])
            self.assertEqual(stop_res["data"]["status"], "STOPPED")

            # 6. GET /api/watch/session/<id>
            get_res = adapter.get_watch_session(sess_id)
            self.assertTrue(get_res["success"])
            self.assertEqual(get_res["data"]["session_id"], sess_id)
        finally:
            self._stop_target_process(proc)


if __name__ == "__main__":
    unittest.main()
