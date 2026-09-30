"""Comprehensive Test Suite for Fast Runtime Snapshot & Offline State Laboratory.

Verifies Tests A through L:
- Test A: Fast capture stop time < 10ms & process resumes.
- Test B: Targeted capture with specified path.
- Test C: Snapshot mutation immutability (S0 untouched when mutating S1).
- Test D: Sibling branch isolation (S0 -> S1, S2 independent).
- Test E: State diff output on snapshot branches.
- Test F: State hash determinism and change on mutation.
- Test G: Hierarchical semantic path resolution (Session.worker.state.counter) & cycle safety.
- Test H: Thread impact analysis (referencing vs potentially affected threads).
- Test I: Live multithread sample capture & continued execution.
- Test J: Timeout safety and fail-open resume.
- Test K: Provenance verification (exact latency breakdown, backend, threads, bytes).
- Test L: GDB backward compatibility.
"""

import os
import signal
import subprocess
import sys
import time
import unittest

from extractor.capture_backend import (
    CaptureLatencyReport,
    CaptureSafetyPolicy,
    GdbCaptureBackend,
    ProcessVmCaptureBackend,
)
from extractor.capture_plan import CaptureMode, CapturePlan, CapturePlanBuilder
from extractor.impact_analyzer import ThreadImpactAnalyzer
from extractor.raw_snapshot import RawRuntimeSnapshot
from extractor.semantic_state import (
    OfflineSemanticEngine,
    SemanticState,
    compute_semantic_state_hash,
)
from extractor.state_lab import SnapshotMutator, StateLaboratory, compute_semantic_diff


class TestFastCaptureAndStateLab(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        cls.sample_src = os.path.join(cls.repo_root, "examples", "sample_multithread.cpp")
        cls.sample_bin = os.path.join(cls.repo_root, "examples", "sample_multithread")

        # Compile multithread sample binary if not already compiled
        if not os.path.exists(cls.sample_bin) or os.path.getmtime(cls.sample_src) > os.path.getmtime(cls.sample_bin):
            res = subprocess.run(
                ["g++", "-g", "-O0", "-pthread", cls.sample_src, "-o", cls.sample_bin],
                capture_output=True,
                text=True,
            )
            if res.returncode != 0:
                raise RuntimeError(f"Failed to compile sample_multithread: {res.stderr}")

    # --------------------------------------------------------------------------
    # Test A: Fast capture stop time < 10ms & process resumes
    # --------------------------------------------------------------------------
    def test_A_fast_capture_stop_time_under_10ms_and_process_resumes(self):
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; [time.sleep(0.01) for _ in range(500)]"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            time.sleep(0.05)
            self.assertIsNone(proc.poll(), "Target process should be running")

            backend = ProcessVmCaptureBackend()
            plan = CapturePlanBuilder.build_full_plan()
            raw_snap = backend.capture(proc.pid, plan)

            lat = raw_snap.latency_report
            self.assertIsNotNone(lat)
            self.assertLess(
                lat.total_stop_time_ms,
                10.0,
                f"Stop time {lat.total_stop_time_ms:.3f}ms exceeded 10ms limit!",
            )

            # Verify target process resumed and is still alive
            self.assertIsNone(proc.poll(), "Process must resume execution after capture")
            os.kill(proc.pid, 0)
        finally:
            proc.terminate()
            proc.wait()

    # --------------------------------------------------------------------------
    # Test B: Targeted capture with specified path
    # --------------------------------------------------------------------------
    def test_B_targeted_capture_with_specified_path(self):
        plan = CapturePlanBuilder.build_targeted_plan(
            target_path="Session.worker.state.counter",
            address=0x10000,
            size=64,
        )

        self.assertEqual(plan.mode, CaptureMode.TARGETED.value)
        self.assertIn("Session.worker.state.counter", plan.target_paths)
        self.assertEqual(len(plan.memory_ranges), 1)
        self.assertEqual(plan.memory_ranges[0][0], 0x10000)

    # --------------------------------------------------------------------------
    # Test C: Snapshot mutation immutability (S0 untouched when mutating S1)
    # --------------------------------------------------------------------------
    def test_C_snapshot_mutation_immutability(self):
        obj0 = {
            "object_id": "obj_state",
            "type": "RuntimeState",
            "address": 0x5000,
            "fields": [
                {"name": "counter", "type": "int", "value": 10},
                {"name": "mode", "type": "int", "value": 1},
                {"name": "state", "type": "int", "value": 1},
            ],
            "primary_path": "g_state",
            "paths": ["g_state"],
        }
        root0 = {"name": "g_state", "type": "RuntimeState", "object_ref": "obj_state"}
        s0 = SemanticState(
            snapshot_id="S0",
            state_hash="hash_s0",
            roots=[root0],
            objects=[obj0],
            semantic_paths={"g_state": "obj_state"},
        )

        mutator = SnapshotMutator()
        s1 = mutator.mutate(s0, "g_state.counter", 50, branch_name="branch_a")

        # Parent S0 must remain 100% immutable
        s0_counter = s0.get_field("obj_state", "counter")["value"]
        self.assertEqual(s0_counter, 10)
        self.assertEqual(s0.snapshot_id, "S0")

        # Child S1 has mutated value
        s1_counter = s1.get_field("obj_state", "counter")["value"]
        self.assertEqual(s1_counter, 50)
        self.assertEqual(s1.branch_info.get("parent_id"), "S0")
        self.assertEqual(s1.branch_info.get("branch_name"), "branch_a")

    # --------------------------------------------------------------------------
    # Test D: Sibling branch isolation (S0 -> S1, S2 independent)
    # --------------------------------------------------------------------------
    def test_D_sibling_branch_isolation(self):
        obj0 = {
            "object_id": "obj_state",
            "type": "RuntimeState",
            "address": 0x5000,
            "fields": [
                {"name": "counter", "type": "int", "value": 10},
                {"name": "state", "type": "int", "value": 1},
            ],
            "primary_path": "g_state",
            "paths": ["g_state"],
        }
        root0 = {"name": "g_state", "type": "RuntimeState", "object_ref": "obj_state"}
        s0 = SemanticState(
            snapshot_id="S0",
            state_hash="hash_s0",
            roots=[root0],
            objects=[obj0],
            semantic_paths={"g_state": "obj_state"},
        )

        mutator = SnapshotMutator()
        # Branch 1: counter = 50
        s1 = mutator.mutate(s0, "g_state.counter", 50, branch_name="branch_high")
        # Sibling Branch 2: counter = -5
        s2 = mutator.mutate(s0, "g_state.counter", -5, branch_name="branch_low")

        # Verify parent state untouched
        self.assertEqual(s0.get_field("obj_state", "counter")["value"], 10)

        # Verify sibling independence
        self.assertEqual(s1.get_field("obj_state", "counter")["value"], 50)
        self.assertEqual(s2.get_field("obj_state", "counter")["value"], -5)
        self.assertNotEqual(s1.state_hash, s2.state_hash)
        self.assertNotEqual(s1.snapshot_id, s2.snapshot_id)

    # --------------------------------------------------------------------------
    # Test E: State diff output on snapshot branches
    # --------------------------------------------------------------------------
    def test_E_state_diff_output_on_snapshot_branches(self):
        obj0 = {
            "object_id": "obj_state",
            "type": "RuntimeState",
            "address": 0x5000,
            "fields": [
                {"name": "counter", "type": "int", "value": 10},
                {"name": "state", "type": "int", "value": 1},
            ],
            "primary_path": "g_state",
            "paths": ["g_state"],
        }
        root0 = {"name": "g_state", "type": "RuntimeState", "object_ref": "obj_state"}
        s0 = SemanticState(
            snapshot_id="S0",
            state_hash="hash_s0",
            roots=[root0],
            objects=[obj0],
            semantic_paths={"g_state": "obj_state"},
        )

        mutator = SnapshotMutator()
        s1 = mutator.mutate(s0, "g_state.counter", 50)

        diff = compute_semantic_diff(s0, s1)
        self.assertEqual(diff["summary"]["value_changes"], 1)
        self.assertEqual(len(diff["changed"]), 1)
        ch = diff["changed"][0]
        self.assertEqual(ch["path"], "g_state.counter")
        self.assertEqual(ch["old_value"], 10)
        self.assertEqual(ch["new_value"], 50)
        self.assertEqual(ch["change_type"], "VALUE_MODIFIED")

    # --------------------------------------------------------------------------
    # Test F: State hash determinism and change on mutation
    # --------------------------------------------------------------------------
    def test_F_state_hash_determinism_and_change_on_mutation(self):
        obj0 = {
            "object_id": "obj_state",
            "type": "RuntimeState",
            "address": 0x5000,
            "fields": [
                {"name": "counter", "type": "int", "value": 10},
                {"name": "state", "type": "int", "value": 1},
            ],
            "primary_path": "g_state",
            "paths": ["g_state"],
        }
        root0 = {"name": "g_state", "type": "RuntimeState", "object_ref": "obj_state"}

        h1 = compute_semantic_state_hash([root0], [obj0])
        h2 = compute_semantic_state_hash([root0], [obj0])
        self.assertEqual(h1, h2, "State hash must be 100% deterministic")

        obj_mut = {
            "object_id": "obj_state",
            "type": "RuntimeState",
            "address": 0x5000,
            "fields": [
                {"name": "counter", "type": "int", "value": 999},
                {"name": "state", "type": "int", "value": 1},
            ],
            "primary_path": "g_state",
            "paths": ["g_state"],
        }
        h_mut = compute_semantic_state_hash([root0], [obj_mut])
        self.assertNotEqual(h1, h_mut, "State hash must change when state is mutated")

    # --------------------------------------------------------------------------
    # Test G: Hierarchical semantic path resolution & cycle safety
    # --------------------------------------------------------------------------
    def test_G_hierarchical_semantic_path_resolution(self):
        # Create hierarchy: Session -> worker -> state -> counter
        counter_obj = {
            "object_id": "obj_counter",
            "type": "int",
            "fields": [{"name": "value", "type": "int", "value": 42}],
        }
        state_obj = {
            "object_id": "obj_state",
            "type": "WorkerState",
            "fields": [{"name": "counter", "type": "int*", "reference": "obj_counter"}],
        }
        worker_obj = {
            "object_id": "obj_worker",
            "type": "Worker",
            "fields": [{"name": "state", "type": "WorkerState*", "reference": "obj_state"}],
        }
        session_obj = {
            "object_id": "obj_session",
            "type": "Session",
            "fields": [{"name": "worker", "type": "Worker*", "reference": "obj_worker"}],
        }
        roots = [{"name": "Session", "type": "Session", "object_ref": "obj_session"}]
        objects = [session_obj, worker_obj, state_obj, counter_obj]

        engine = OfflineSemanticEngine()
        paths_by_obj, _ = engine._build_semantic_paths(roots, objects)

        self.assertIn("Session", paths_by_obj["obj_session"])
        self.assertIn("Session.worker", paths_by_obj["obj_worker"])
        self.assertIn("Session.worker.state", paths_by_obj["obj_state"])
        self.assertIn("Session.worker.state.counter", paths_by_obj["obj_counter"])

        # Test cycle safety: A -> B -> A
        nodeA = {
            "object_id": "A",
            "type": "Node",
            "fields": [{"name": "b", "type": "Node*", "reference": "B"}],
        }
        nodeB = {
            "object_id": "B",
            "type": "Node",
            "fields": [{"name": "a", "type": "Node*", "reference": "A"}],
        }
        roots_cycle = [{"name": "RootA", "type": "Node", "object_ref": "A"}]
        cycle_paths, _ = engine._build_semantic_paths(roots_cycle, [nodeA, nodeB])
        self.assertIn("RootA", cycle_paths["A"])
        self.assertIn("RootA.b", cycle_paths["B"])

    # --------------------------------------------------------------------------
    # Test H: Thread impact analysis (referencing vs potentially affected threads)
    # --------------------------------------------------------------------------
    def test_H_thread_impact_analysis(self):
        shared_obj = {
            "object_id": "obj_session",
            "type": "Session",
            "fields": [{"name": "retry", "type": "int", "value": 2}],
            "primary_path": "Session",
            "paths": ["Session"],
            "storage": "static",
        }
        w1_obj = {
            "object_id": "obj_w1",
            "type": "Worker",
            "fields": [{"name": "session", "type": "Session*", "reference": "obj_session"}],
            "primary_path": "Worker1",
            "paths": ["Worker1"],
        }
        w2_obj = {
            "object_id": "obj_w2",
            "type": "Worker",
            "fields": [{"name": "session", "type": "Session*", "reference": "obj_session"}],
            "primary_path": "Worker2",
            "paths": ["Worker2"],
        }

        state = SemanticState(
            snapshot_id="S0",
            state_hash="hash0",
            roots=[
                {"name": "Session", "type": "Session", "object_ref": "obj_session"},
                {"name": "Worker1", "type": "Worker", "object_ref": "obj_w1"},
                {"name": "Worker2", "type": "Worker", "object_ref": "obj_w2"},
            ],
            objects=[shared_obj, w1_obj, w2_obj],
            semantic_paths={
                "Session": "obj_session",
                "Worker1": "obj_w1",
                "Worker2": "obj_w2",
            },
            references=[
                {"from_id": "obj_w1", "to_id": "obj_session", "field": "session"},
                {"from_id": "obj_w2", "to_id": "obj_session", "field": "session"},
            ],
            threads=[
                {"thread_id": 1001, "name": "worker_1", "function": "worker_func"},
                {"thread_id": 1002, "name": "worker_2", "function": "worker_func"},
                {"thread_id": 1003, "name": "isolated_worker", "function": "idle_func"},
            ],
        )

        report = ThreadImpactAnalyzer.analyze(state, target="Session.retry", new_value=5)

        self.assertIn("Session.retry", report["directly_affected_objects"])
        self.assertIn("Session", report["shared_objects"])
        self.assertIn("worker_1", report["referencing_threads"])
        self.assertTrue(report["observed_impact"]["verified"])
        self.assertFalse(report["potential_impact"]["verified"])
        self.assertEqual(report["thread_isolation_status"], "POTENTIAL_IMPACT_ANALYSIS_ONLY")

    # --------------------------------------------------------------------------
    # Test I: Live multithread sample capture & continued execution
    # --------------------------------------------------------------------------
    def test_I_live_multithread_sample_capture_and_continued_execution(self):
        env = {**os.environ, "SAMPLE_HOLD_MS": "2500"}
        proc = subprocess.Popen(
            [self.sample_bin],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        try:
            # Wait for 3 worker threads to be spawned
            time.sleep(0.15)
            self.assertIsNone(proc.poll(), "Sample process should be running")

            backend = ProcessVmCaptureBackend()
            plan = CapturePlanBuilder.build_full_plan()
            raw_snap = backend.capture(proc.pid, plan)

            # Assert thread count is 4 (main + 3 workers)
            self.assertGreaterEqual(len(raw_snap.thread_metadata), 4)

            # Assert stop time < 10ms
            self.assertLess(raw_snap.latency_report.total_stop_time_ms, 10.0)

            # Assert process continues executing after capture
            self.assertIsNone(proc.poll(), "Target process must continue running after capture")
            os.kill(proc.pid, 0)
        finally:
            proc.terminate()
            proc.wait()

    # --------------------------------------------------------------------------
    # Test J: Timeout safety and fail-open resume
    # --------------------------------------------------------------------------
    def test_J_timeout_safety_and_fail_open_resume(self):
        from unittest.mock import patch

        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; [time.sleep(0.01) for _ in range(500)]"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            time.sleep(0.05)
            policy = CaptureSafetyPolicy(max_stop_time_ms=10)
            backend = ProcessVmCaptureBackend()
            plan = CapturePlanBuilder.build_full_plan()

            with patch("extractor.capture_backend._read_proc_maps", side_effect=RuntimeError("Simulated failure during suspend")):
                with self.assertRaises(RuntimeError):
                    backend.capture(proc.pid, plan, policy=policy)

            # Target process MUST have been resumed by the finally: block
            time.sleep(0.05)
            self.assertIsNone(proc.poll(), "Target process must have resumed despite error")
            os.kill(proc.pid, 0)
        finally:
            proc.terminate()
            proc.wait()

    # --------------------------------------------------------------------------
    # Test K: Provenance verification (exact latency, backend, bytes, threads)
    # --------------------------------------------------------------------------
    def test_K_provenance_verification(self):
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; [time.sleep(0.01) for _ in range(500)]"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            time.sleep(0.05)
            backend = ProcessVmCaptureBackend()
            plan = CapturePlanBuilder.build_full_plan()
            raw_snap = backend.capture(proc.pid, plan)

            prov = raw_snap.provenance
            self.assertIn("latency_report", prov)
            lat = prov["latency_report"]
            self.assertIn("stop_latency_ms", lat)
            self.assertIn("thread_metadata_latency_ms", lat)
            self.assertIn("memory_capture_latency_ms", lat)
            self.assertIn("resume_latency_ms", lat)
            self.assertIn("total_stop_time_ms", lat)

            self.assertEqual(raw_snap.capture_backend, "process_vm_readv")
            self.assertGreater(raw_snap.provenance["captured_bytes"], 0)
            self.assertGreaterEqual(len(raw_snap.thread_metadata), 1)
        finally:
            proc.terminate()
            proc.wait()

    # --------------------------------------------------------------------------
    # Test L: GDB backward compatibility
    # --------------------------------------------------------------------------
    def test_L_gdb_backward_compatibility(self):
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; [time.sleep(0.01) for _ in range(500)]"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            time.sleep(0.05)
            backend = GdbCaptureBackend()
            plan = CapturePlanBuilder.build_full_plan()
            raw_snap = backend.capture(proc.pid, plan)

            self.assertEqual(raw_snap.pid, proc.pid)
            self.assertEqual(raw_snap.capture_backend, "gdb")
            self.assertIn("latency_report", raw_snap.provenance)
            self.assertLess(raw_snap.latency_report.total_stop_time_ms, 10.0)
        finally:
            proc.terminate()
            proc.wait()


if __name__ == "__main__":
    unittest.main()
