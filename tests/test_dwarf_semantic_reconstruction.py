"""Integration and Unit Tests for DWARF + RawRuntimeSnapshot Real C++ Object Graph Reconstruction.

Tests:
1. DWARF indexing and type hierarchy
2. Stripped runtime binary + external unstripped DWARF
3. Symbol mismatch rejection (build ID validation)
4. PIE / ASLR runtime address resolution and load bias
5. Pointer graphs and stable object identity
6. Cyclic graphs (A <-> B) and shared objects (A -> C, B -> C)
7. Memory-not-captured partial state propagation (zero fabrication)
8. CLI end-to-end analyze command
9. StateLaboratory mutation and diff on real C++ semantic state
"""

import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import unittest

from extractor.capture_backend import ProcessVmCaptureBackend, ProcfsCaptureBackend
from extractor.cpp_decoder import CppObjectDecoder, DwarfRuntimeResolver
from extractor.debug_image import inspect_elf
from extractor.dwarf_indexer import DwarfIndex, DwarfIndexer
from extractor.raw_snapshot import RawRuntimeSnapshot
from extractor.semantic_state import OfflineSemanticEngine, SemanticState, compute_semantic_state_hash
from extractor.state_lab import SnapshotMutator, StateLaboratory, compute_semantic_diff
from extractor.typed_memory_reader import TypedMemoryReader


class TestDwarfSemanticReconstruction(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work_dir = tempfile.mkdtemp(prefix="ds_dwarf_test_")
        cls.sample_src = os.path.abspath("examples/sample_dwarf_target.cpp")
        cls.cycle_src = os.path.abspath("examples/sample_pointer_cycle_target.cpp")

        # 1. Compile sample_dwarf_target (unstripped)
        cls.dwarf_unstripped = os.path.join(cls.work_dir, "sample_dwarf_unstripped")
        cmd_compile = ["g++", "-g", "-O0", cls.sample_src, "-o", cls.dwarf_unstripped]
        subprocess.run(cmd_compile, check=True)

        # 2. Extract external DWARF debug artifact
        cls.dwarf_debug = os.path.join(cls.work_dir, "sample_dwarf.debug")
        subprocess.run(["objcopy", "--only-keep-debug", cls.dwarf_unstripped, cls.dwarf_debug], check=True)

        # 3. Create stripped runtime binary
        cls.dwarf_stripped = os.path.join(cls.work_dir, "sample_dwarf_stripped")
        subprocess.run(["strip", "--strip-all", cls.dwarf_unstripped, "-o", cls.dwarf_stripped], check=True)

        # 4. Compile PIE binary
        cls.pie_bin = os.path.join(cls.work_dir, "sample_pie")
        subprocess.run(["g++", "-fPIE", "-pie", "-g", "-O0", cls.sample_src, "-o", cls.pie_bin], check=True)

        # 5. Compile cycle and pointer binary
        cls.cycle_bin = os.path.join(cls.work_dir, "sample_cycle")
        subprocess.run(["g++", "-g", "-O0", cls.cycle_src, "-o", cls.cycle_bin], check=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.work_dir, ignore_errors=True)

    def test_01_dwarf_index_and_hierarchy(self):
        """Verify offline DWARF indexing builds complete type and variable hierarchies."""
        index = DwarfIndexer.get_index(self.dwarf_debug)

        self.assertIsNotNone(index.build_id)
        self.assertIn("Session", index.types_by_name)
        self.assertIn("Worker", index.types_by_name)
        self.assertIn("State", index.types_by_name)

        session_t = index.types_by_name["Session"][0]
        self.assertEqual(len(session_t.members), 1)
        self.assertEqual(session_t.members[0].name, "worker")
        self.assertEqual(session_t.members[0].offset, 0)

        worker_t = index.types_by_name["Worker"][0]
        self.assertEqual(len(worker_t.members), 1)
        self.assertEqual(worker_t.members[0].name, "state")
        self.assertEqual(worker_t.members[0].offset, 0)

        state_t = index.types_by_name["State"][0]
        self.assertEqual(len(state_t.members), 1)
        self.assertEqual(state_t.members[0].name, "counter")
        self.assertEqual(state_t.members[0].offset, 0)

        globals_by_name = {v.name: v for v in index.global_variables}
        self.assertIn("g_session", globals_by_name)
        self.assertIsNotNone(globals_by_name["g_session"].link_time_address)

    def test_02_stripped_runtime_matching_debug_image(self):
        """Verify stripped production binary + external matching DWARF companion."""
        # 1. Verify build ID identity match
        id_stripped = inspect_elf(self.dwarf_stripped)
        id_debug = inspect_elf(self.dwarf_debug)
        self.assertIsNotNone(id_stripped.build_id)
        self.assertEqual(id_stripped.build_id, id_debug.build_id)

        # 2. Launch stripped runtime process
        proc = subprocess.Popen([self.dwarf_stripped], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            time.sleep(0.1)  # Ensure g_session.worker.state.counter = 42 is written

            # 3. Capture process memory using fast capture backend
            backend = ProcessVmCaptureBackend()
            if not backend.is_available(proc.pid):
                backend = ProcfsCaptureBackend()

            snapshot = backend.capture(pid=proc.pid)
            self.assertEqual(snapshot.pid, proc.pid)
            self.assertGreater(len(snapshot._buffers), 0)

            # Target process was resumed immediately after capture!
            self.assertIsNone(proc.poll(), "Target process must remain running after capture")

            # 4. Offline reconstruction using external DWARF companion
            engine = OfflineSemanticEngine()
            state = engine.reconstruct(
                raw_snapshot=snapshot,
                debug_image=self.dwarf_debug,
            )

            # 5. Verify semantic correctness
            self.assertEqual(state.provenance.get("status"), "COMPLETE")
            self.assertFalse(state.provenance.get("synthetic"))
            self.assertEqual(len(state.roots), 1)
            self.assertEqual(state.roots[0]["name"], "g_session")

            # Find state object and counter field
            state_obj = state.get_object_by_path("g_session.worker.state")
            self.assertIsNotNone(state_obj, "Hierarchical path g_session.worker.state must be resolved")

            counter_field = state.get_field(state_obj["object_id"], "counter")
            self.assertIsNotNone(counter_field)
            self.assertEqual(counter_field["value"], 42, "Value 42 must come directly from captured bytes")
            self.assertEqual(counter_field["status"], "RESOLVED")
            self.assertEqual(counter_field["provenance"]["source"], "RAW_SNAPSHOT")

            # Total objects: Session, Worker, State (3 objects)
            self.assertEqual(len(state.objects), 3)

        finally:
            if proc.stdout:
                proc.stdout.close()
            if proc.stderr:
                proc.stderr.close()
            proc.kill()
            proc.wait()

    def test_03_symbol_mismatch_rejection(self):
        """Verify that mismatched DWARF artifacts are strictly rejected."""
        # Create dummy snapshot with intentional bogus build ID
        snap = RawRuntimeSnapshot(
            snapshot_id="S_MISMATCH",
            pid=99999,
            executable=self.dwarf_stripped,
            executable_build_id="00112233445566778899aabbccddeeff00112233",
            timestamp="2026-09-30T12:00:00Z",
            capture_duration_us=10.0,
        )

        # 1. Default: strict validation rejects
        engine = OfflineSemanticEngine()
        state = engine.reconstruct(
            raw_snapshot=snap,
            debug_image=self.dwarf_debug,
            allow_symbol_mismatch=False,
        )
        self.assertEqual(state.provenance.get("status"), "SYMBOL_MISMATCH")
        self.assertEqual(len(state.objects), 0)
        self.assertTrue(any(d.get("code") == "SYMBOL_MISMATCH" for d in state.provenance.get("diagnostics", [])))

        # 2. Explicit override permits analysis with warning
        state_perm = engine.reconstruct(
            raw_snapshot=snap,
            debug_image=self.dwarf_debug,
            allow_symbol_mismatch=True,
        )
        self.assertNotEqual(state_perm.provenance.get("status"), "SYMBOL_MISMATCH")
        self.assertTrue(any(d.get("code") == "SYMBOL_MISMATCH_IGNORED" for d in state_perm.provenance.get("diagnostics", [])))

    def test_04_pie_aslr_load_bias(self):
        """Verify PIE binaries correctly calculate load bias from runtime memory mappings."""
        proc = subprocess.Popen([self.pie_bin], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            time.sleep(0.1)

            backend = ProcessVmCaptureBackend()
            if not backend.is_available(proc.pid):
                backend = ProcfsCaptureBackend()

            snapshot = backend.capture(pid=proc.pid)

            resolver = DwarfRuntimeResolver(snapshot, self.pie_bin)
            index = DwarfIndexer.get_index(self.pie_bin)
            load_bias = resolver.calculate_load_bias(index)

            # In PIE binaries, load_bias must be non-zero and equal to binary base mapping
            self.assertGreater(load_bias, 0, "PIE runtime load bias must be non-zero")

            res = resolver.resolve()
            self.assertEqual(res.status, "COMPLETE")
            self.assertEqual(len(res.roots), 1)

            # Root address must be biased
            link_addr = index.variables_by_name["g_session"][0].link_time_address
            self.assertEqual(res.roots[0]["address"], link_addr + load_bias)

            # Decode g_session.worker.state.counter == 42
            state_obj = next(o for o in res.objects if o.get("type") == "State")
            counter_f = next(f for f in state_obj.get("fields", []) if f.get("name") == "counter")
            self.assertEqual(counter_f["value"], 42)
        finally:
            if proc.stdout:
                proc.stdout.close()
            if proc.stderr:
                proc.stderr.close()
            proc.kill()
            proc.wait()

    def test_05_pointer_graph_and_stable_object_identity(self):
        """Verify pointer edges and stable shared object identity (A -> C and B -> C)."""
        proc = subprocess.Popen([self.cycle_bin], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            time.sleep(0.1)

            backend = ProcessVmCaptureBackend()
            if not backend.is_available(proc.pid):
                backend = ProcfsCaptureBackend()

            snapshot = backend.capture(pid=proc.pid)

            engine = OfflineSemanticEngine()
            state = engine.reconstruct(snapshot, debug_image=self.cycle_bin)

            # Both g_node_a and g_node_b point to g_shared
            obj_a = state.get_object_by_path("g_node_a")
            obj_b = state.get_object_by_path("g_node_b")
            self.assertIsNotNone(obj_a)
            self.assertIsNotNone(obj_b)

            f_shared_a = next(f for f in obj_a["fields"] if f["name"] == "shared")
            f_shared_b = next(f for f in obj_b["fields"] if f["name"] == "shared")

            # Shared object must have ONE identical object_id
            self.assertIsNotNone(f_shared_a.get("object_ref"))
            self.assertEqual(f_shared_a.get("object_ref"), f_shared_b.get("object_ref"))

            shared_obj = state.get_object(f_shared_a["object_ref"])
            self.assertIsNotNone(shared_obj)
            self.assertEqual(shared_obj["type"], "SharedNode")

            f_shared_val = next(f for f in shared_obj["fields"] if f["name"] == "shared_val")
            self.assertEqual(f_shared_val["value"], 777)
        finally:
            if proc.stdout:
                proc.stdout.close()
            if proc.stderr:
                proc.stderr.close()
            proc.kill()
            proc.wait()

    def test_06_cyclic_graph_recursion_safety(self):
        """Verify cyclic references (A -> B -> A) do not cause infinite recursion."""
        proc = subprocess.Popen([self.cycle_bin], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            time.sleep(0.1)

            backend = ProcessVmCaptureBackend()
            if not backend.is_available(proc.pid):
                backend = ProcfsCaptureBackend()

            snapshot = backend.capture(pid=proc.pid)

            engine = OfflineSemanticEngine()
            # Reconstruction must terminate cleanly and deterministically
            state = engine.reconstruct(snapshot, debug_image=self.cycle_bin)

            obj_a = state.get_object_by_path("g_node_a")
            obj_b = state.get_object_by_path("g_node_b")

            f_next_b = next(f for f in obj_a["fields"] if f["name"] == "next_b")
            f_next_a = next(f for f in obj_b["fields"] if f["name"] == "next_a")

            self.assertEqual(f_next_b["object_ref"], obj_b["object_id"])
            self.assertEqual(f_next_a["object_ref"], obj_a["object_id"])
        finally:
            if proc.stdout:
                proc.stdout.close()
            if proc.stderr:
                proc.stderr.close()
            proc.kill()
            proc.wait()

    def test_07_memory_not_captured_partial_propagation(self):
        """Verify uncaptured memory propagates PARTIAL status without fabricating zero values."""
        index = DwarfIndexer.get_index(self.dwarf_debug)
        g_session_addr = index.variables_by_name["g_session"][0].link_time_address

        # Create snapshot covering Session and Worker, but NOT State.counter
        snap = RawRuntimeSnapshot(
            snapshot_id="S_PARTIAL_TEST",
            pid=55555,
            executable=self.dwarf_stripped,
            executable_build_id=index.build_id,
            timestamp="2026-09-30T12:00:00Z",
            capture_duration_us=10.0,
            memory_regions=[{
                "start": 0x0,
                "end": 0x100000,
                "permissions": "r-xp",
                "category": "binary",
                "pathname": self.dwarf_stripped,
            }]
        )
        # Register NO buffers! Entire g_session is uncaptured.
        engine = OfflineSemanticEngine()
        state = engine.reconstruct(snap, debug_image=self.dwarf_debug)

        # 1. State status must be PARTIAL
        self.assertEqual(state.provenance.get("status"), "PARTIAL")

        # 2. Diagnostics must explicitly record MEMORY_NOT_CAPTURED
        diag = state.provenance.get("diagnostics", [])
        self.assertTrue(any(d.get("code") == "MEMORY_NOT_CAPTURED" for d in diag))

        # 3. Field value must be None, NOT 0
        state_obj = state.get_object_by_path("g_session.worker.state")
        self.assertIsNotNone(state_obj)
        self.assertEqual(state_obj.get("status"), "PARTIAL")

        counter_f = state.get_field(state_obj["object_id"], "counter")
        self.assertIsNone(counter_f["value"], "Never fabricate zero data for uncaptured memory")
        self.assertEqual(counter_f["status"], "MEMORY_NOT_CAPTURED")

    def test_08_cli_analyze_flow(self):
        """Verify dynamic-state analyze CLI command outputs exact formatted semantic tree."""
        # Create a captured snapshot on disk
        index = DwarfIndexer.get_index(self.dwarf_debug)
        g_session_addr = index.variables_by_name["g_session"][0].link_time_address

        snap_dir = os.path.join(self.work_dir, "snap_cli_test")
        snap = RawRuntimeSnapshot(
            snapshot_id="RS_000001",
            pid=12345,
            executable=self.dwarf_stripped,
            executable_build_id=index.build_id,
            timestamp="2026-09-30T12:00:00Z",
            capture_duration_us=15.0,
            memory_regions=[{
                "start": 0x0,
                "end": 0x100000,
                "permissions": "r-xp",
                "category": "binary",
                "pathname": self.dwarf_stripped,
            }]
        )
        snap.register_buffer(g_session_addr, struct.pack("<i", 42))
        snap.save(snap_dir)

        # Run CLI command
        cli_bin = os.path.abspath("bin/dynamic-state")
        cmd = [
            sys.executable,
            cli_bin,
            "analyze",
            "--snapshot", snap_dir,
            "--debug-image", self.dwarf_debug,
            "--show-roots",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
        out = proc.stdout

        self.assertIn("Semantic State", out)
        self.assertIn("g_session", out)
        self.assertIn("worker", out)
        self.assertIn("state", out)
        self.assertIn("counter: 42", out)
        self.assertIn("Status: COMPLETE", out)
        self.assertIn("Objects: 3", out)
        self.assertIn("Roots: 1", out)
        self.assertIn("Diagnostics: 0", out)

    def test_09_state_lab_integration_mutation_and_diff(self):
        """Verify real C++ semantic state integrates seamlessly with State Laboratory."""
        index = DwarfIndexer.get_index(self.dwarf_debug)
        g_session_addr = index.variables_by_name["g_session"][0].link_time_address

        snap = RawRuntimeSnapshot(
            snapshot_id="RS_PARENT",
            pid=12345,
            executable=self.dwarf_stripped,
            executable_build_id=index.build_id,
            timestamp="2026-09-30T12:00:00Z",
            capture_duration_us=15.0,
            memory_regions=[{
                "start": 0x0,
                "end": 0x100000,
                "permissions": "r-xp",
                "category": "binary",
                "pathname": self.dwarf_stripped,
            }]
        )
        snap.register_buffer(g_session_addr, struct.pack("<i", 42))

        engine = OfflineSemanticEngine()
        parent_state = engine.reconstruct(snap, debug_image=self.dwarf_debug)

        # Verify parent state hash is deterministic
        parent_hash_1 = parent_state.state_hash
        parent_hash_2 = compute_semantic_state_hash(parent_state.roots, parent_state.objects, parent_state.threads)
        self.assertEqual(parent_hash_1, parent_hash_2)

        # Mutate via StateLaboratory: Session.worker.state.counter -> 999
        lab = StateLaboratory()
        lab.add_snapshot(parent_state)
        child_state, _ = lab.mutate(
            parent_id="RS_PARENT",
            target="g_session.worker.state.counter",
            new_value=999,
            branch_name="Counter_Mutation_Branch"
        )

        # Parent remains strictly immutable (counter == 42)
        p_state_obj = parent_state.get_object_by_path("g_session.worker.state")
        p_counter = parent_state.get_field(p_state_obj["object_id"], "counter")
        self.assertEqual(p_counter["value"], 42)

        # Child has counter == 999
        c_state_obj = child_state.get_object_by_path("g_session.worker.state")
        c_counter = child_state.get_field(c_state_obj["object_id"], "counter")
        self.assertEqual(c_counter["value"], 999)

        # State hash changes deterministically
        self.assertNotEqual(parent_state.state_hash, child_state.state_hash)

        # Compute semantic diff
        diff = compute_semantic_diff(parent_state, child_state)
        self.assertEqual(diff["summary"]["value_changes"], 1)
        self.assertEqual(diff["changed"][0]["field"], "counter")
        self.assertEqual(diff["changed"][0]["old_value"], 42)
        self.assertEqual(diff["changed"][0]["new_value"], 999)


if __name__ == "__main__":
    unittest.main()
