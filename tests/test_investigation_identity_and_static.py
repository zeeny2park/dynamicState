"""Automated tests for Debug Image/Build ID Validation, Load Bias, and Static Code Correlation.

Tests acceptance criterion:
- Explicit module identity validation (VERIFIED_MATCH, MISMATCH, TARGET_ID_UNAVAILABLE, DEBUG_ID_UNAVAILABLE, INCOMPLETE)
- Deterministic PIE load bias resolution and ambiguous mapping handling
- Separation of type definition from code relationships
- PID-only authorization requirements and ephemeral session persistence reporting
"""

import os
import unittest

from extractor.debug_image import BinaryIdentity
from extractor.investigation import InvestigationManager, InvestigationSession
from extractor.modules import LoadBiasResolutionError, ModuleAddressResolver, RuntimeModule
from extractor.static_analyzer import (
    IDENTITY_DEBUG_ID_UNAVAILABLE,
    IDENTITY_INCOMPLETE,
    IDENTITY_MISMATCH,
    IDENTITY_TARGET_ID_UNAVAILABLE,
    IDENTITY_VERIFIED_MATCH,
    LINK_KIND_CALL_RELATIONSHIP,
    LINK_KIND_FIELD_WRITE_CANDIDATE,
    LINK_KIND_FUNCTION_ADDRESS,
    LINK_KIND_GLOBAL_VARIABLE,
    LINK_KIND_TYPE_DEFINITION,
    LINK_KIND_UNRESOLVED,
    DwarfStaticAnalysisProvider,
    MockStaticAnalysisProvider,
    NullStaticAnalysisProvider,
    get_static_provider,
    validate_module_identity,
)


class TestIdentityMismatchAndStaticAnalysis(unittest.TestCase):
    """Test identity mismatch detection, load bias validation, and static-code linkage."""

    def test_explicit_identity_validation_states(self):
        # 1. VERIFIED_MATCH
        status, reason = validate_module_identity("build_123", "build_123")
        self.assertEqual(status, IDENTITY_VERIFIED_MATCH)
        self.assertIn("match", reason.lower())

        # 2. MISMATCH
        status, reason = validate_module_identity("build_123", "build_456")
        self.assertEqual(status, IDENTITY_MISMATCH)
        self.assertIn("conflict", reason.lower())

        # 3. TARGET_ID_UNAVAILABLE (Debug ID exists, target ID does not)
        status, reason = validate_module_identity(None, "build_456")
        self.assertEqual(status, IDENTITY_TARGET_ID_UNAVAILABLE)
        self.assertIn("does not prove a match", reason)

        # 4. DEBUG_ID_UNAVAILABLE (Target ID exists, debug ID does not)
        status, reason = validate_module_identity("build_123", None)
        self.assertEqual(status, IDENTITY_DEBUG_ID_UNAVAILABLE)

        # 5. INCOMPLETE (Neither target nor debug ID available)
        status, reason = validate_module_identity(None, None)
        self.assertEqual(status, IDENTITY_INCOMPLETE)

    def test_build_id_mismatch_prevents_silent_decode(self):
        module_mismatch = RuntimeModule(
            module_id="app_worker",
            path="/app/prod_worker",
            runtime_base=0x555555554000,
            runtime_end=0x555555560000,
            load_bias=0x555555554000,
            build_id="aabbccdd11223344",
            load_bias_status="RESOLVED",
            build_id_status=IDENTITY_MISMATCH,
        )

        mock_provider = MockStaticAnalysisProvider()
        runtime_addr = 0x555555554000 + 0x1140

        res = mock_provider.resolve_runtime_to_code(runtime_addr, module=module_mismatch)
        self.assertEqual(res["status"], "UNRESOLVED_BUILD_ID_MISMATCH")
        self.assertEqual(res["link_kind"], LINK_KIND_UNRESOLVED)
        self.assertFalse(res["is_verified"])
        self.assertIsNone(res["link_basis"])
        self.assertIn("mismatches debug image", res["reason"])

    def test_unresolved_load_bias_reported_honestly(self):
        module_unresolved = RuntimeModule(
            module_id="app_worker",
            path="/app/prod_worker",
            runtime_base=0x555555554000,
            runtime_end=0x555555560000,
            load_bias=None,
            build_id="11223344aabbccdd",
            load_bias_status="UNRESOLVED",
            build_id_status=IDENTITY_VERIFIED_MATCH,
        )

        mock_provider = MockStaticAnalysisProvider()
        runtime_addr = 0x555555554000 + 0x1140

        res = mock_provider.resolve_runtime_to_code(runtime_addr, module=module_unresolved)
        self.assertEqual(res["status"], "UNRESOLVED_LOAD_BIAS")
        self.assertEqual(res["link_kind"], LINK_KIND_UNRESOLVED)
        self.assertFalse(res["is_verified"])
        self.assertIsNone(res["link_basis"])
        self.assertIn("UNRESOLVED load bias", res["reason"])

    def test_pie_load_bias_calculation_two_distinct_biases(self):
        elf_info = BinaryIdentity(
            path="/app/test_pie",
            elf_class="ELF64",
            architecture="x86_64",
            endianness="little",
            elf_type="ET_DYN",
            pt_loads=[{"p_vaddr": 0x0, "p_offset": 0, "p_filesz": 0x2000, "p_memsz": 0x2000}],
        )

        # Case 1: PIE load bias 1 at 0x600000000000
        mappings_1 = [{"start_addr": 0x600000000000, "end_addr": 0x600000002000, "offset": 0}]
        bias_1 = ModuleAddressResolver.calculate_load_bias(mappings_1, elf_info)
        self.assertEqual(bias_1, 0x600000000000)

        # Case 2: PIE load bias 2 at 0x700000000000
        mappings_2 = [{"start_addr": 0x700000000000, "end_addr": 0x700000002000, "offset": 0}]
        bias_2 = ModuleAddressResolver.calculate_load_bias(mappings_2, elf_info)
        self.assertEqual(bias_2, 0x700000000000)

        # Negative / ambiguous case: empty mappings
        with self.assertRaises(LoadBiasResolutionError):
            ModuleAddressResolver.calculate_load_bias([], elf_info)

    def test_type_definition_separated_from_function_relationships(self):
        module_ok = RuntimeModule(
            module_id="app_worker",
            path="/app/prod_worker",
            runtime_base=0x600000000000,
            runtime_end=0x600000010000,
            load_bias=0x600000000000,
            build_id="11223344aabbccdd",
            load_bias_status="RESOLVED",
            build_id_status=IDENTITY_VERIFIED_MATCH,
        )

        mock_provider = MockStaticAnalysisProvider()
        runtime_addr = 0x600000000000 + 0x5000

        # Type match establishes TYPE_DEFINITION only, not function ownership
        res = mock_provider.resolve_runtime_to_code(runtime_addr, module=module_ok, type_name="WorkerState")
        self.assertEqual(res["status"], "RESOLVED_TYPE_MATCH")
        self.assertEqual(res["link_kind"], LINK_KIND_TYPE_DEFINITION)
        self.assertFalse(res["is_relationship_candidate"])
        self.assertIn("does NOT prove function ownership", res["relationship_limitation"])

    def test_disassembly_text_search_candidate_only(self):
        dwarf_prov = DwarfStaticAnalysisProvider(debug_artifact_path="/nonexistent/empty.elf")
        # Direct verify that disassembly refs are candidate only
        raw_disasm = [
            "0000000000001140 <worker_thread>:",
            "  1144: mov [rax], 0x1  # g_worker_state",
        ]
        refs = dwarf_prov.find_references("g_worker_state", disassembly_text="\n".join(raw_disasm))
        self.assertEqual(len(refs), 1)
        ref = refs[0]
        self.assertEqual(ref["link_kind"], LINK_KIND_FIELD_WRITE_CANDIDATE)
        self.assertTrue(ref["is_candidate_only"])
        self.assertFalse(ref["is_verified"])
        self.assertIn("candidate reference only", ref["limitation"])

    def test_defensible_static_code_linkage(self):
        module_ok = RuntimeModule(
            module_id="app_worker",
            path="/app/prod_worker",
            runtime_base=0x555555554000,
            runtime_end=0x555555560000,
            load_bias=0x555555554000,
            build_id="11223344aabbccdd",
            load_bias_status="RESOLVED",
            build_id_status=IDENTITY_VERIFIED_MATCH,
        )

        mock_provider = MockStaticAnalysisProvider()
        static_elf_addr = 0x1140
        hex_static = "0x{:x}".format(static_elf_addr)

        mock_provider.functions[hex_static] = {
            "name": "worker_run_loop",
            "file": "worker.cpp",
            "line": 42,
        }

        runtime_addr = module_ok.load_bias + static_elf_addr

        res = mock_provider.resolve_runtime_to_code(runtime_addr, module=module_ok)
        self.assertEqual(res["status"], "RESOLVED")
        self.assertEqual(res["link_kind"], LINK_KIND_FUNCTION_ADDRESS)
        self.assertTrue(res["is_verified"])
        self.assertEqual(res["symbol_name"], "worker_run_loop")
        self.assertEqual(res["source_file"], "worker.cpp")
        self.assertEqual(res["line_number"], 42)
        self.assertEqual(res["link_basis"], "mock_static_address_match")
        self.assertEqual(res["static_address"], hex_static)

    def test_unresolved_address_not_in_symbols(self):
        module_ok = RuntimeModule(
            module_id="app_worker",
            path="/app/prod_worker",
            runtime_base=0x555555554000,
            runtime_end=0x555555560000,
            load_bias=0x555555554000,
            build_id="11223344aabbccdd",
            load_bias_status="RESOLVED",
            build_id_status=IDENTITY_VERIFIED_MATCH,
        )

        mock_provider = MockStaticAnalysisProvider()
        runtime_addr = module_ok.load_bias + 0x9999

        res = mock_provider.resolve_runtime_to_code(runtime_addr, module=module_ok)
        self.assertEqual(res["status"], "UNRESOLVED_ADDRESS_NOT_FOUND")
        self.assertEqual(res["link_kind"], LINK_KIND_UNRESOLVED)
        self.assertFalse(res["is_verified"])
        self.assertIsNone(res["link_basis"])
        self.assertIn("not found in mock symbols", res["reason"])

    def test_pid_only_authorization_and_process_existence(self):
        mgr = InvestigationManager()

        # 1. PID without authorization -> BLOCKED
        sess_unauth = mgr.start_investigation(
            goal="Test unauthenticated live capture",
            pid=12345,
            authorize_target=False,
        )
        self.assertEqual(sess_unauth["status"], "BLOCKED")
        self.assertEqual(sess_unauth["stages"]["target_identity"]["status"], "BLOCKED")
        self.assertIn("authorize_target=True", sess_unauth["stages"]["target_identity"]["details"]["error"])

        # 2. PID with authorization but non-existent PID -> FAILED with ESRCH
        sess_esrch = mgr.start_investigation(
            goal="Test non-existent PID live capture",
            pid=999999999,
            authorize_target=True,
        )
        self.assertEqual(sess_esrch["status"], "FAILED")
        self.assertEqual(sess_esrch["stages"]["target_identity"]["status"], "FAILED")
        self.assertIn("ESRCH", sess_esrch["stages"]["target_identity"]["details"]["error"])

    def test_session_persistence_reported_honestly_as_ephemeral(self):
        mgr = InvestigationManager()
        sess = mgr.start_investigation(goal="Check session persistence")
        self.assertEqual(sess["persistence"], "EPHEMERAL_PROCESS_LOCAL")

    def test_investigation_manager_handles_build_id_mismatch(self):
        mgr = InvestigationManager()
        session = mgr.start_investigation(
            goal="Investigate memory with mismatched debug image",
            debug_image="/nonexistent/mismatched_debug.elf",
        )
        self.assertIn(session["status"], ("COMPLETED", "PARTIAL", "FAILED"))
        ident = session["stages"]["target_identity"]["details"]
        self.assertEqual(ident["build_id_status"], IDENTITY_INCOMPLETE)


if __name__ == "__main__":
    unittest.main()
