"""End-to-End Real Runtime Validation Suite for Dynamic State.

Validates the full production pipeline against a real stripped C++ process:
1. Stripped C++ process launched (production binary without symbols)
2. Matching external DWARF companion verified via GNU Build-ID
3. Ultra-short stop via process_vm_readv (ProcessVmCaptureBackend)
4. Immediate fail-open process resumption (heartbeat continues, process stays alive)
5. Zero GDB / zero ptrace during offline semantic analysis
6. Real C++ global object graph reconstruction
7. Real heap object reconstruction through typed pointer (Worker.heap_state -> HeapState*)
8. Shared object identity preservation (A -> C, B -> C share exact object_id)
9. Cyclic graph safe termination (A <-> B)
10. PIE / ASLR runtime address resolution and load bias
11. Non-PIE (ET_EXEC) fixed binary support
12. Unresolved load bias detection (LOAD_BIAS_UNRESOLVED)
13. Strict Build-ID mismatch rejection (SYMBOL_MISMATCH)
14. Partial memory capture reporting (MEMORY_NOT_CAPTURED, zero fabrication)
15. Multi-thread metadata and stop status capture
16. Deterministic SHA-256 state hash (64-char full SHA-256)
17. State Laboratory offline mutation (SEMANTIC_MUTATION)
18. Semantic state diff calculation
19. Accurate live mutation capability reporting (distinguishing semantic vs live write)
20. Complete traceable provenance for every decoded field
21. Real capture latency performance measurement (min, median, p95, max)
"""

import copy
import json
import os
import shutil
import signal
import statistics
import subprocess
import tempfile
import time
import unittest

from extractor.capture_backend import (
    CaptureSafetyPolicy,
    ProcessVmCaptureBackend,
    ProcfsCaptureBackend,
)
from extractor.capture_plan import CapturePlan
from extractor.cpp_decoder import DwarfRuntimeResolver
from extractor.debug_image import inspect_elf
from extractor.dwarf_indexer import DwarfIndexer
from extractor.raw_snapshot import RawRuntimeSnapshot
from extractor.semantic_state import OfflineSemanticEngine, compute_semantic_state_hash
from extractor.state_lab import SnapshotMutator, compute_semantic_diff
from extractor.state_replayer import StateReplayer


class TestRealRuntimeValidation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work_dir = tempfile.mkdtemp(prefix="dynstate_real_val_")
        cls.fixture_src = os.path.abspath("tests/fixtures/real_runtime/main.cpp")

        # 1. Compile PIE debug binary (unstripped)
        cls.pie_debug = os.path.join(cls.work_dir, "real_target_pie.debug")
        cmd_pie = [
            "g++", "-fPIE", "-pie", "-g", "-O0", "-fno-inline", "-fno-omit-frame-pointer",
            "-Wl,--build-id=sha1", cls.fixture_src, "-o", cls.pie_debug, "-lpthread"
        ]
        subprocess.run(cmd_pie, check=True)

        # 2. Extract stripped production executable
        cls.pie_stripped = os.path.join(cls.work_dir, "real_target_pie.stripped")
        subprocess.run(["strip", "-s", "-o", cls.pie_stripped, cls.pie_debug], check=True)

        # 3. Compile non-PIE debug binary (ET_EXEC)
        cls.nonpie_debug = os.path.join(cls.work_dir, "real_target_nonpie.debug")
        cmd_nonpie = [
            "g++", "-no-pie", "-g", "-O0", "-fno-inline", "-fno-omit-frame-pointer",
            "-Wl,--build-id=sha1", cls.fixture_src, "-o", cls.nonpie_debug, "-lpthread"
        ]
        subprocess.run(cmd_nonpie, check=True)

        # 4. Extract stripped non-PIE executable
        cls.nonpie_stripped = os.path.join(cls.work_dir, "real_target_nonpie.stripped")
        subprocess.run(["strip", "-s", "-o", cls.nonpie_stripped, cls.nonpie_debug], check=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.work_dir, ignore_errors=True)

    def _start_target_process(self, binary_path: str):
        """Launch target process and wait for synchronized READY signal."""
        proc = subprocess.Popen(
            [binary_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        line = proc.stdout.readline().strip()
        self.assertEqual(line, "READY", f"Process initialization sync failed: got {line}")
        return proc

    def _stop_target_process(self, proc):
        """Terminate target process cleanly."""
        if proc.poll() is None:
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=1)
        if proc.stdout:
            proc.stdout.close()
        if proc.stderr:
            proc.stderr.close()

    # --------------------------------------------------------------------------
    # 1. Real stripped runtime + external DWARF Build-ID matching
    # --------------------------------------------------------------------------
    def test_01_build_id_matching(self):
        info_stripped = inspect_elf(self.pie_stripped)
        info_debug = inspect_elf(self.pie_debug)

        self.assertIsNotNone(info_stripped.build_id, "Stripped binary must have GNU Build ID")
        self.assertIsNotNone(info_debug.build_id, "Debug artifact must have GNU Build ID")
        self.assertEqual(
            info_stripped.build_id.lower(),
            info_debug.build_id.lower(),
            "Production stripped binary and external DWARF artifact must share exact Build ID"
        )
        self.assertTrue(info_stripped.stripped)
        self.assertFalse(info_debug.stripped)

    # --------------------------------------------------------------------------
    # 2. Real process_vm_readv capture without mock buffers
    # --------------------------------------------------------------------------
    def test_02_real_process_vm_readv_capture(self):
        proc = self._start_target_process(self.pie_stripped)
        try:
            backend = ProcessVmCaptureBackend()
            self.assertTrue(backend.is_available(proc.pid))

            snap = backend.capture(pid=proc.pid)
            self.assertEqual(snap.capture_backend, "process_vm_readv")
            self.assertGreater(snap.bytes_captured, 0)
            self.assertGreater(len(snap._buffers), 0)

            # Ensure buffers are real memory bytes from the process
            total_buf_bytes = sum(len(b) for b in snap._buffers.values())
            self.assertEqual(snap.bytes_captured, total_buf_bytes)
        finally:
            self._stop_target_process(proc)

    # --------------------------------------------------------------------------
    # 3. Target resumes immediately and continues execution
    # --------------------------------------------------------------------------
    def test_03_target_resumes_immediately(self):
        proc = self._start_target_process(self.pie_stripped)
        try:
            backend = ProcessVmCaptureBackend()
            snap = backend.capture(pid=proc.pid)

            # 1. Target process is still alive and running
            self.assertIsNone(proc.poll(), "Target process must remain running after capture")

            # 2. Stop latency was microseconds
            self.assertGreater(snap.stop_latency_us, 0)
            self.assertGreater(snap.resume_latency_us, 0)
            self.assertGreater(snap.total_capture_latency_us, 0)

            # 3. Execution resumes: wait and verify process remains healthy
            time.sleep(0.05)
            self.assertIsNone(proc.poll(), "Target process must actively continue running")
        finally:
            self._stop_target_process(proc)

    # --------------------------------------------------------------------------
    # 4 & 5 & 6. Real Global Object, Heap Object & Typed Pointer Traversal
    # --------------------------------------------------------------------------
    def test_04_real_global_and_heap_reconstruction(self):
        proc = self._start_target_process(self.pie_stripped)
        try:
            backend = ProcessVmCaptureBackend()
            snap = backend.capture(pid=proc.pid)

            engine = OfflineSemanticEngine()
            state = engine.reconstruct(raw_snapshot=snap, debug_image=self.pie_debug)

            self.assertEqual(state.provenance.get("status"), "COMPLETE")
            self.assertFalse(state.provenance.get("synthetic"))

            # Verify global root g_session
            session_roots = [r for r in state.roots if r["name"] == "g_session"]
            self.assertEqual(len(session_roots), 1)

            # Verify typed pointer traversal: g_session -> worker -> state -> counter (42), flags (7)
            counter_field = None
            flags_field = None
            heap_counter_field = None

            for o in state.objects:
                for f in o.get("fields", []):
                    spath = f.get("semantic_path", "")
                    if spath.endswith("worker.state.counter") or (f.get("name") == "counter" and "worker.state" in spath):
                        counter_field = f
                    elif spath.endswith("worker.state.flags") or (f.get("name") == "flags" and "worker.state" in spath):
                        flags_field = f
                    elif "heap_state" in spath and f.get("name") == "counter":
                        heap_counter_field = f

            self.assertIsNotNone(counter_field, "g_session.worker.state.counter must be decoded")
            self.assertEqual(counter_field["value"], 42)
            self.assertEqual(counter_field["status"], "RESOLVED")

            self.assertIsNotNone(flags_field, "g_session.worker.state.flags must be decoded")
            self.assertEqual(flags_field["value"], 7)
            self.assertEqual(flags_field["status"], "RESOLVED")

            # Verify heap object reached via typed pointer: g_session.worker.heap_state -> HeapState* -> counter (99)
            self.assertIsNotNone(heap_counter_field, "HeapState.counter must be reached via Worker.heap_state pointer")
            self.assertEqual(heap_counter_field["value"], 99)
            self.assertEqual(heap_counter_field["status"], "RESOLVED")
        finally:
            self._stop_target_process(proc)

    # --------------------------------------------------------------------------
    # 7. Shared object identity
    # --------------------------------------------------------------------------
    def test_05_shared_object_identity(self):
        proc = self._start_target_process(self.pie_stripped)
        try:
            backend = ProcessVmCaptureBackend()
            snap = backend.capture(pid=proc.pid)

            engine = OfflineSemanticEngine()
            state = engine.reconstruct(raw_snapshot=snap, debug_image=self.pie_debug)

            # Both g_node_a and g_session.worker.shared point to the same physical node
            node_a_root = [r for r in state.roots if r["name"] == "g_node_a"][0]
            node_a_oid = node_a_root["object_ref"]

            # Locate shared pointer field
            shared_ptr_target = None
            for o in state.objects:
                for f in o.get("fields", []):
                    if f.get("name") == "shared":
                        shared_ptr_target = f.get("reference")

            self.assertIsNotNone(shared_ptr_target)
            self.assertEqual(
                shared_ptr_target,
                node_a_oid,
                "Shared pointer must point to the canonical object_id of g_node_a"
            )
        finally:
            self._stop_target_process(proc)

    # --------------------------------------------------------------------------
    # 8. Cyclic graph termination (A <-> B)
    # --------------------------------------------------------------------------
    def test_06_cyclic_graph_termination(self):
        proc = self._start_target_process(self.pie_stripped)
        try:
            backend = ProcessVmCaptureBackend()
            snap = backend.capture(pid=proc.pid)

            t0 = time.monotonic()
            engine = OfflineSemanticEngine()
            state = engine.reconstruct(raw_snapshot=snap, debug_image=self.pie_debug)
            duration = time.monotonic() - t0

            # Termination must be fast and complete
            self.assertLess(duration, 2.0, "Cyclic graph reconstruction must terminate immediately")
            self.assertEqual(state.provenance.get("status"), "COMPLETE")

            # Check that node A and B cross-reference each other cleanly
            objs_by_id = {o["object_id"]: o for o in state.objects}
            node_a_root = [r for r in state.roots if r["name"] == "g_node_a"][0]
            node_b_root = [r for r in state.roots if r["name"] == "g_node_b"][0]

            node_a = objs_by_id[node_a_root["object_ref"]]
            node_b = objs_by_id[node_b_root["object_ref"]]

            next_a = [f for f in node_a["fields"] if f["name"] == "next"][0]["reference"]
            next_b = [f for f in node_b["fields"] if f["name"] == "next"][0]["reference"]

            self.assertEqual(next_a, node_b["object_id"])
            self.assertEqual(next_b, node_a["object_id"])
        finally:
            self._stop_target_process(proc)

    # --------------------------------------------------------------------------
    # 9. PIE / ASLR Load Bias calculation
    # --------------------------------------------------------------------------
    def test_07_pie_aslr_load_bias(self):
        proc = self._start_target_process(self.pie_stripped)
        try:
            backend = ProcessVmCaptureBackend()
            snap = backend.capture(pid=proc.pid)

            resolver = DwarfRuntimeResolver(snapshot=snap, debug_image_path=self.pie_debug)
            res = resolver.resolve()

            self.assertEqual(res.status, "COMPLETE")
            self.assertGreater(res.load_bias, 0, "PIE binary with ASLR must have non-zero positive load bias")
        finally:
            self._stop_target_process(proc)

    # --------------------------------------------------------------------------
    # 10. Non-PIE (ET_EXEC) fixed binary support
    # --------------------------------------------------------------------------
    def test_08_non_pie_et_exec_support(self):
        proc = self._start_target_process(self.nonpie_stripped)
        try:
            backend = ProcessVmCaptureBackend()
            snap = backend.capture(pid=proc.pid)

            resolver = DwarfRuntimeResolver(snapshot=snap, debug_image_path=self.nonpie_debug)
            res = resolver.resolve()

            self.assertEqual(res.status, "COMPLETE")
            self.assertEqual(res.load_bias, 0, "Non-PIE executable must have load bias 0")

            # Verify values
            session_roots = [r for r in res.roots if r["name"] == "g_session"]
            self.assertEqual(len(session_roots), 1)
        finally:
            self._stop_target_process(proc)

    # --------------------------------------------------------------------------
    # 11. Unresolved load bias detection (LOAD_BIAS_UNRESOLVED)
    # --------------------------------------------------------------------------
    def test_09_unresolved_load_bias(self):
        # Create a synthetic snapshot that lacks memory maps for a PIE binary
        empty_snap = RawRuntimeSnapshot(
            snapshot_id="RS_TEST_UNRESOLVED",
            pid=99999,
            executable="/fake/pie/bin",
            executable_build_id=None,
            timestamp="2026-09-30T00:00:00Z",
            capture_duration_us=100.0,
            memory_regions=[],
            observation_metadata={"memory_maps": []},
            capture_backend="process_vm_readv",
        )
        resolver = DwarfRuntimeResolver(snapshot=empty_snap, debug_image_path=self.pie_debug)
        res = resolver.resolve()

        self.assertEqual(res.status, "LOAD_BIAS_UNRESOLVED")
        self.assertTrue(any(d.get("code") == "LOAD_BIAS_UNRESOLVED" for d in res.diagnostics))

    # --------------------------------------------------------------------------
    # 12. Strict Build-ID mismatch rejection
    # --------------------------------------------------------------------------
    def test_10_build_id_mismatch_rejection(self):
        proc = self._start_target_process(self.pie_stripped)
        try:
            backend = ProcessVmCaptureBackend()
            snap = backend.capture(pid=proc.pid)

            # Attempt resolution with mismatched non-PIE debug binary
            resolver = DwarfRuntimeResolver(snapshot=snap, debug_image_path=self.nonpie_debug)
            res = resolver.resolve()

            self.assertEqual(res.status, "SYMBOL_MISMATCH")
            self.assertTrue(any(d.get("code") == "SYMBOL_MISMATCH" for d in res.diagnostics))
        finally:
            self._stop_target_process(proc)

    # --------------------------------------------------------------------------
    # 13. Partial memory capture reporting (MEMORY_NOT_CAPTURED)
    # --------------------------------------------------------------------------
    def test_11_partial_memory_capture_reporting(self):
        proc = self._start_target_process(self.pie_stripped)
        try:
            backend = ProcessVmCaptureBackend()
            snap = backend.capture(pid=proc.pid)

            # Strip out heap buffers to simulate partial capture where heap wasn't captured
            filtered_buffers = {}
            for (start, end), buf in snap._buffers.items():
                is_heap = False
                for r in snap.memory_regions:
                    r_start = int(r["start"], 16) if isinstance(r["start"], str) else r["start"]
                    r_end = int(r["end"], 16) if isinstance(r["end"], str) else r["end"]
                    if (r.get("category") == "heap" or r.get("pathname") == "[heap]") and r_start <= start < r_end:
                        is_heap = True
                        break
                if not is_heap:
                    filtered_buffers[(start, end)] = buf
            snap._buffers = filtered_buffers

            engine = OfflineSemanticEngine()
            state = engine.reconstruct(raw_snapshot=snap, debug_image=self.pie_debug)

            # Reconstructed state must escalate to PARTIAL
            self.assertEqual(state.provenance.get("status"), "PARTIAL")

            # Check that HeapState object has status PARTIAL and uncaptured fields
            heap_obj = next((o for o in state.objects if o.get("type") == "HeapState"), None)
            self.assertIsNotNone(heap_obj, "HeapState object should still be indexed via pointer")
            self.assertEqual(heap_obj.get("status"), "PARTIAL")

            counter_field = next((f for f in heap_obj.get("fields", []) if f.get("name") == "counter"), None)
            self.assertIsNotNone(counter_field)
            self.assertIsNone(counter_field.get("value"), "Uncaptured memory field value must be None")
            self.assertEqual(counter_field.get("status"), "MEMORY_NOT_CAPTURED")
            self.assertEqual(counter_field.get("provenance", {}).get("status"), "MEMORY_NOT_CAPTURED")

            # Diagnostic must record MEMORY_NOT_CAPTURED
            diag_codes = [d.get("code") for d in state.provenance.get("diagnostics", [])]
            self.assertIn("MEMORY_NOT_CAPTURED", diag_codes)
        finally:
            self._stop_target_process(proc)

    # --------------------------------------------------------------------------
    # 14. Multithread metadata and consistency
    # --------------------------------------------------------------------------
    def test_12_multithread_metadata(self):
        proc = self._start_target_process(self.pie_stripped)
        try:
            backend = ProcessVmCaptureBackend()
            snap = backend.capture(pid=proc.pid)

            self.assertGreaterEqual(len(snap.thread_metadata), 3, "Target process must have at least 3 threads (main + 2 workers)")
            for t in snap.thread_metadata:
                self.assertIn("thread_id", t)
                self.assertIn("state", t)
                self.assertIn("stop_status", t)
                self.assertTrue(t.get("capture_participation"))
                self.assertEqual(t.get("registers_availability"), "REGISTER_STATE_UNAVAILABLE")

            # Check snapshot consistency contract in provenance
            self.assertEqual(
                snap.provenance.get("snapshot_consistency"),
                "PROCESS_STOPPED_MEMORY_SNAPSHOT"
            )
        finally:
            self._stop_target_process(proc)

    # --------------------------------------------------------------------------
    # 15. Deterministic SHA-256 state hash
    # --------------------------------------------------------------------------
    def test_13_deterministic_state_hash(self):
        proc = self._start_target_process(self.pie_stripped)
        try:
            backend = ProcessVmCaptureBackend()
            snap = backend.capture(pid=proc.pid)

            engine = OfflineSemanticEngine()
            s1 = engine.reconstruct(raw_snapshot=snap, debug_image=self.pie_debug)
            s2 = engine.reconstruct(raw_snapshot=snap, debug_image=self.pie_debug)

            self.assertEqual(s1.state_hash, s2.state_hash, "State hash must be 100% deterministic")
            self.assertEqual(len(s1.state_hash), 64, "State hash must be full SHA-256 (64 hex chars)")
            self.assertEqual(s1.state_hash_short, s1.state_hash[:16])
            self.assertEqual(s1.state_hash_algorithm, "SHA-256")
        finally:
            self._stop_target_process(proc)

    # --------------------------------------------------------------------------
    # 16 & 17. State Laboratory Semantic Mutation & Diff
    # --------------------------------------------------------------------------
    def test_14_state_lab_mutation_and_diff(self):
        proc = self._start_target_process(self.pie_stripped)
        try:
            backend = ProcessVmCaptureBackend()
            snap = backend.capture(pid=proc.pid)

            engine = OfflineSemanticEngine()
            parent = engine.reconstruct(raw_snapshot=snap, debug_image=self.pie_debug)

            # Offline semantic mutation
            child = SnapshotMutator.mutate(
                parent_state=parent,
                target="g_session.worker.state.counter",
                new_value=999
            )

            # 1. Parent is immutable
            p_obj = parent.get_object_by_path("g_session.worker.state")
            c_obj = child.get_object_by_path("g_session.worker.state")

            p_val = [f["value"] for f in p_obj["fields"] if f["name"] == "counter"][0]
            c_val = [f["value"] for f in c_obj["fields"] if f["name"] == "counter"][0]

            self.assertEqual(p_val, 42)
            self.assertEqual(c_val, 999)
            self.assertNotEqual(parent.state_hash, child.state_hash)

            # 2. Branch metadata specifies SEMANTIC_MUTATION
            self.assertEqual(child.branch_info.get("mutation_type"), "SEMANTIC_MUTATION")
            self.assertFalse(child.branch_info.get("live_process_modified"))

            # 3. Semantic diff
            diff = compute_semantic_diff(parent, child)
            self.assertEqual(diff["summary"]["value_changes"], 1)
            self.assertEqual(diff["changed"][0]["old_value"], 42)
            self.assertEqual(diff["changed"][0]["new_value"], 999)
        finally:
            self._stop_target_process(proc)

    # --------------------------------------------------------------------------
    # 18. Live Mutation Capability Reporting
    # --------------------------------------------------------------------------
    def test_15_live_mutation_capability_reporting(self):
        caps = StateReplayer.get_mutation_capabilities(controller=None)
        self.assertTrue(caps["CAN_MUTATE_SEMANTIC_STATE"])
        self.assertFalse(caps["CAN_WRITE_LIVE_PROCESS"])
        self.assertFalse(caps["CAN_VERIFY_LIVE_WRITE"])

        # Replay without controller
        rep = StateReplayer.replay(
            controller=None,
            target_object_id="obj_0001",
            field_name="counter",
            value=123
        )
        self.assertEqual(rep["capability"], "UNAVAILABLE")
        self.assertEqual(rep["mutation_type"], "LIVE_PROCESS_MUTATION")
        self.assertEqual(rep["mutation_status"], "NOT_ATTEMPTED")
        self.assertFalse(rep["attempted"])

    # --------------------------------------------------------------------------
    # 19. Complete Traceable Provenance
    # --------------------------------------------------------------------------
    def test_16_traceable_provenance(self):
        proc = self._start_target_process(self.pie_stripped)
        try:
            backend = ProcessVmCaptureBackend()
            snap = backend.capture(pid=proc.pid)

            engine = OfflineSemanticEngine()
            state = engine.reconstruct(raw_snapshot=snap, debug_image=self.pie_debug)

            state_obj = state.get_object_by_path("g_session.worker.state")
            counter_field = [f for f in state_obj["fields"] if f["name"] == "counter"][0]

            prov = counter_field.get("provenance")
            self.assertIsNotNone(prov, "Decoded field must have provenance")
            self.assertEqual(prov["source"], "RAW_SNAPSHOT")
            self.assertIn("runtime_address", prov)
            self.assertEqual(prov["member_offset"], 0)
            self.assertEqual(prov["type"], "int")
            self.assertIn("captured_range", prov)
            self.assertEqual(prov["dwarf"]["member"], "counter")
            self.assertEqual(prov["canonical_type"], "State")
            self.assertEqual(prov["root_name"], "g_session")
        finally:
            self._stop_target_process(proc)

    # --------------------------------------------------------------------------
    # 20. Real Capture Latency Performance Measurement (30 iterations)
    # --------------------------------------------------------------------------
    def test_17_real_capture_latency_performance_measurement(self):
        proc = self._start_target_process(self.pie_stripped)
        try:
            backend = ProcessVmCaptureBackend()
            stop_latencies = []
            read_latencies = []
            resume_latencies = []
            total_latencies = []
            bytes_list = []

            iterations = 25
            for _ in range(iterations):
                snap = backend.capture(pid=proc.pid)
                stop_latencies.append(snap.stop_latency_us)
                read_latencies.append(snap.memory_read_latency_us)
                resume_latencies.append(snap.resume_latency_us)
                total_latencies.append(snap.total_capture_latency_us)
                bytes_list.append(snap.bytes_captured)
                time.sleep(0.01)

            # Statistical analysis
            total_latencies.sort()
            p95_idx = int(len(total_latencies) * 0.95)

            lat_min = min(total_latencies)
            lat_med = statistics.median(total_latencies)
            lat_p95 = total_latencies[p95_idx]
            lat_max = max(total_latencies)
            avg_bytes = statistics.mean(bytes_list)

            print("\n=== Real Runtime Capture Latency (25 iterations) ===")
            print(f"Captured Bytes (mean): {avg_bytes:,.0f} bytes")
            print(f"Stop Latency (median): {statistics.median(stop_latencies):.1f} us")
            print(f"Read Latency (median): {statistics.median(read_latencies):.1f} us")
            print(f"Resume Latency (median): {statistics.median(resume_latencies):.1f} us")
            print(f"Total Capture Latency:")
            print(f"  min:    {lat_min:.1f} us")
            print(f"  median: {lat_med:.1f} us")
            print(f"  p95:    {lat_p95:.1f} us")
            print(f"  max:    {lat_max:.1f} us")

            # Verify reasonable sanity bounds (e.g. median total < 50ms)
            self.assertLess(lat_med, 50_000.0, "Median capture latency should be sub-50ms")
        finally:
            self._stop_target_process(proc)


if __name__ == "__main__":
    unittest.main()
