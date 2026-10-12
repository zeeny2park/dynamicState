"""Regression and integration tests for Snapshot Explorer & Code Navigation UX.

Validates the full navigation pipeline:
Finding -> C++ Object -> Field -> DWARF Type / Source Location -> Related Function Candidates.

Verifies:
1. DWARF indexing of declaration file/line for types, members, variables, and subprograms.
2. C++ object graph decoding propagating decl_file and decl_line to decoded objects and fields.
3. Candidate function correlation with 4 explicit evidence tiers (observed, static, indirect, unknown).
4. Layout mutation caveat enforcement (DWARF declaration line != field mutation site).
5. REST API endpoint GET /api/objects/{object_id}/code-navigation.
6. Object Inspector enrichment (display_name, field interpretation, code_navigation).
7. InvestigationFinding optional fields (priority, uncertainty, thread_id, execution_context).
"""

import os
import unittest
from typing import Any, Dict

from extractor.dwarf_indexer import DwarfIndexer, DwarfType, DwarfMember
from extractor.cpp_decoder import CppObjectDecoder
from extractor.typed_memory_reader import TypedMemoryReader
from extractor.raw_snapshot import RawRuntimeSnapshot, RawMemoryRegion
from extractor.investigation import InvestigationFinding
from extractor.static_analyzer import (
    EVIDENCE_LEVEL_OBSERVED,
    EVIDENCE_LEVEL_STATIC,
    EVIDENCE_LEVEL_INDIRECT,
    EVIDENCE_LEVEL_UNKNOWN,
    LAYOUT_MUTATION_CAVEAT,
    FunctionCandidate,
    MockStaticAnalysisProvider,
    DwarfStaticAnalysisProvider,
    resolve_function_candidates,
)
from extractor.agent_runtime import AgentRuntime
from extractor.web.server import WebApiAdapter


class TestSnapshotCodeNavigation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.elf_path = os.path.abspath("build/app_debug.elf")
        cls.has_elf = os.path.exists(cls.elf_path)

    def test_01_dwarf_indexer_file_table_and_subprograms(self):
        """Verify DwarfIndexer indexes file table and subprograms from real ELF."""
        if not self.has_elf:
            self.skipTest("build/app_debug.elf not available")

        index = DwarfIndexer.get_index(self.elf_path)
        self.assertIsNotNone(index.file_table)
        self.assertGreater(len(index.file_table), 0)

        # Confirm main.cpp or fixture file is present
        file_paths = list(index.file_table.values())
        self.assertTrue(any("main.cpp" in f for f in file_paths), f"main.cpp not found in {file_paths}")

        # Check subprograms
        self.assertGreater(len(index.subprograms), 0)
        subp_names = [s.name for s in index.subprograms]
        self.assertTrue(any("worker" in n.lower() or "main" in n.lower() for n in subp_names))

        # Check State struct type declaration
        state_types = index.types_by_name.get("State", [])
        self.assertGreater(len(state_types), 0)
        state_t = state_types[0]
        self.assertTrue(state_t.decl_file and "main.cpp" in state_t.decl_file)
        self.assertEqual(state_t.decl_line, 8)

        # Check member declaration
        counter_m = next((m for m in state_t.members if m.name == "counter"), None)
        self.assertIsNotNone(counter_m)
        self.assertTrue(counter_m.decl_file and "main.cpp" in counter_m.decl_file)
        self.assertEqual(counter_m.decl_line, 9)

    def test_02_cpp_decoder_propagates_decl_locations(self):
        """Verify CppObjectDecoder annotates object and fields with decl_file and decl_line."""
        if not self.has_elf:
            self.skipTest("build/app_debug.elf not available")

        index = DwarfIndexer.get_index(self.elf_path)
        state_t = index.types_by_name["State"][0]

        # Create dummy snapshot memory containing State struct (16 bytes: counter=42, flags=1)
        raw_bytes = (42).to_bytes(4, "little") + (1).to_bytes(4, "little") + b"\x00" * 8
        raw_snap = RawRuntimeSnapshot(
            snapshot_id="test_snap_01",
            timestamp="2026-10-11T05:00:00Z",
            pid=1000,
            executable=self.elf_path,
            executable_build_id=index.build_id,
            memory_regions=[{
                "region_id": "R1",
                "start": "0x5000",
                "end": hex(0x5000 + len(raw_bytes)),
                "size": len(raw_bytes),
                "permissions": "rw-p",
                "category": "heap",
            }],
            register_state={},
            captured_ranges=[[0x5000, 0x5000 + len(raw_bytes)]],
            raw_memory={"total_bytes": len(raw_bytes)},
            capture_backend="process_vm_readv",
            observation_metadata={},
            completeness="COMPLETE",
            capture_duration_us=100.0,
            provenance={},
            _buffers={(0x5000, 0x5000 + len(raw_bytes)): raw_bytes},
        )

        reader = TypedMemoryReader(raw_snap, pointer_size=index.pointer_size, endianness=index.endianness)
        decoder = CppObjectDecoder(reader, index, load_bias=0)
        obj_id = decoder.decode_object(
            address=0x5000,
            type_offset=state_t.die_offset,
            path="main::g_state",
            storage="heap",
            custom_name="g_state (State)",
        )

        obj = decoder.objects_by_id[obj_id]
        self.assertEqual(obj["display_name"], "g_state (State)")
        self.assertTrue(obj["decl_file"] and "main.cpp" in obj["decl_file"])
        self.assertEqual(obj["decl_line"], 8)

        # Verify fields have decl_file and decl_line
        self.assertEqual(len(obj["fields"]), 2)
        counter_f = next(f for f in obj["fields"] if f["name"] == "counter")
        self.assertEqual(counter_f["value"], 42)
        self.assertTrue(counter_f["decl_file"] and "main.cpp" in counter_f["decl_file"])
        self.assertEqual(counter_f["decl_line"], 9)
        self.assertIsNone(counter_f.get("type_decl_line"))

    def test_03_candidate_function_evidence_tiers(self):
        """Verify resolve_function_candidates categorizes candidates into observed, static, indirect, unknown."""
        # 1. Observed: on thread call stack
        mock_snapshot = {
            "execution": {
                "threads": [
                    {
                        "thread_id": 101,
                        "frames": [
                            {"level": 0, "function": "State::process_request", "location": "main.cpp:55"},
                            {"level": 1, "function": "server_loop", "location": "server.cpp:120"},
                        ],
                    }
                ]
            }
        }

        # Mock static provider
        mock_prov = MockStaticAnalysisProvider()
        mock_prov.functions["0x401000"] = {
            "name": "State::update_counter",
            "file": "main.cpp",
            "line": 40,
        }
        mock_prov.references["counter"] = [
            {
                "caller_function": "mutate_counter_direct",
                "source_location": "worker.cpp:88",
                "reference_site": "mov dword ptr [rdi], 0x1",
            }
        ]
        mock_prov.calls["mutate_counter_direct"] = {
            "callers": ["dispatcher_task"],
            "callees": [],
            "status": "RESOLVED",
        }

        target_obj = {
            "object_id": "obj_001",
            "type": "State",
            "display_name": "State@0x5000",
            "address": 0x5000,
            "decl_file": "main.cpp",
            "decl_line": 8,
            "fields": [
                {"name": "counter", "type": "int", "decl_file": "main.cpp", "decl_line": 9}
            ],
        }

        result = resolve_function_candidates(
            target_object=target_obj,
            target_field="counter",
            snapshot=mock_snapshot,
            static_provider=mock_prov,
        )

        # Verify layout caveat is present
        self.assertEqual(result["layout_caveat"], LAYOUT_MUTATION_CAVEAT)
        self.assertIn("struct memory layout only", result["layout_caveat"])
        self.assertIn("does NOT prove where this field was mutated", result["layout_caveat"])

        candidates = result["candidates"]
        cand_map = {c["function_name"]: c for c in candidates}

        # Observed tier
        self.assertIn("State::process_request", cand_map)
        self.assertEqual(cand_map["State::process_request"]["evidence_level"], EVIDENCE_LEVEL_OBSERVED)
        self.assertEqual(cand_map["State::process_request"]["thread_id"], 101)
        self.assertIn("Active on Thread 101", cand_map["State::process_request"]["reason"])
        self.assertIn("runtime mutation of this specific field remains unverified", cand_map["State::process_request"]["limitations"])

        # Static tier (disassembly reference)
        self.assertIn("mutate_counter_direct", cand_map)
        self.assertEqual(cand_map["mutate_counter_direct"]["evidence_level"], EVIDENCE_LEVEL_STATIC)
        self.assertEqual(cand_map["mutate_counter_direct"]["basis_source"], "disassembly_reference")

        # Indirect tier (caller of static function)
        self.assertIn("dispatcher_task", cand_map)
        self.assertEqual(cand_map["dispatcher_task"]["evidence_level"], EVIDENCE_LEVEL_INDIRECT)
        self.assertEqual(cand_map["dispatcher_task"]["basis_source"], "call_graph_reference")

        # Tier counts
        self.assertGreaterEqual(result["counts_by_tier"][EVIDENCE_LEVEL_OBSERVED], 1)
        self.assertGreaterEqual(result["counts_by_tier"][EVIDENCE_LEVEL_STATIC], 1)
        self.assertGreaterEqual(result["counts_by_tier"][EVIDENCE_LEVEL_INDIRECT], 1)

    def test_04_real_dwarf_candidate_resolution(self):
        """Verify candidate resolution with real DwarfStaticAnalysisProvider."""
        if not self.has_elf:
            self.skipTest("build/app_debug.elf not available")

        prov = DwarfStaticAnalysisProvider(self.elf_path)
        self.assertTrue(prov.is_available())

        target_obj = {
            "object_id": "obj_001",
            "type": "State",
            "address": 0x5000,
            "decl_file": "main.cpp",
            "decl_line": 8,
            "fields": [
                {"name": "counter", "type": "int", "decl_file": "main.cpp", "decl_line": 9}
            ],
        }

        result = resolve_function_candidates(
            target_object=target_obj,
            target_field="counter",
            snapshot=None,
            static_provider=prov,
        )

        self.assertIn("layout_caveat", result)
        self.assertEqual(result["target_type"], "State")
        self.assertEqual(result["target_field"], "counter")
        self.assertEqual(result["field_decl_line"], 9)

    def test_05_server_code_navigation_api(self):
        """Verify WebApiAdapter.get_code_navigation endpoint returns valid JSON schema."""
        runtime = AgentRuntime()
        adapter = WebApiAdapter(runtime)

        # Create a mock snapshot in runtime corpus
        snap_data = {
            "schema_version": "0.3",
            "snapshot_id": "snap_test_nav",
            "process": {"pid": 2000, "binary": self.elf_path if self.has_elf else "/bin/test"},
            "provenance": {"debug_image_path": self.elf_path if self.has_elf else None},
            "execution": {"threads": [{"thread_id": 1, "frames": [{"level": 0, "function": "test_fn", "location": "test.cpp:10"}]}]},
            "persistent": {
                "roots": [{"name": "g_obj", "kind": "global"}],
                "objects": [
                    {
                        "object_id": "obj_nav_01",
                        "type": "Worker",
                        "address": 0x7000,
                        "hex_address": "0x7000",
                        "size": 32,
                        "decl_file": "worker.cpp",
                        "decl_line": 15,
                        "display_name": "Worker@0x7000",
                        "fields": [
                            {"name": "status", "type": "int", "value": 1, "decl_file": "worker.cpp", "decl_line": 18, "status": "RESOLVED"}
                        ],
                    }
                ],
            },
        }

        # Store in corpus
        runtime.corpus.add(snap_data)

        # Call get_code_navigation
        nav_res = adapter.get_code_navigation("obj_nav_01", field_name="status", snapshot_id="snap_test_nav")
        self.assertTrue(nav_res["success"])
        data = nav_res["data"]
        self.assertEqual(data["target_object_id"], "obj_nav_01")
        self.assertEqual(data["target_field"], "status")
        self.assertEqual(data["field_decl_file"], "worker.cpp")
        self.assertEqual(data["field_decl_line"], 18)
        self.assertIn("layout_caveat", data)
        self.assertIn("candidates", data)

        # Call inspect_object to verify enrichment
        insp_res = adapter.inspect_object("obj_nav_01", snapshot_id="snap_test_nav")
        self.assertTrue(insp_res["success"])
        obj_data = insp_res["data"]
        self.assertEqual(obj_data["display_name"], "Worker@0x7000")
        self.assertEqual(obj_data["decl_file"], "worker.cpp")
        self.assertEqual(obj_data["decl_line"], 15)
        self.assertIn("code_navigation", obj_data)
        self.assertIn("function_candidates", obj_data)

        # Verify field interpretation
        status_f = obj_data["fields"][0]
        self.assertEqual(status_f["interpretation"], "observed")
        self.assertEqual(status_f["decl_file"], "worker.cpp")
        self.assertEqual(status_f["decl_line"], 18)

    def test_06_investigation_finding_optional_attributes(self):
        """Verify InvestigationFinding supports priority, uncertainty, thread_id, execution_context."""
        finding = InvestigationFinding(
            finding_id="f_001",
            category="fact",
            title="Suspicious counter reset",
            description="Counter value changed from 10 to 0",
            priority="HIGH",
            uncertainty="Possible memory corruption",
            thread_id=42,
            execution_context="worker_thread_42",
        )
        d = finding.to_dict()
        self.assertEqual(d["priority"], "HIGH")
        self.assertEqual(d["uncertainty"], "Possible memory corruption")
        self.assertEqual(d["thread_id"], 42)
        self.assertEqual(d["execution_context"], "worker_thread_42")


if __name__ == "__main__":
    unittest.main()
