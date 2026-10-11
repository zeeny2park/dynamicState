"""Automated tests for Debug Image/Build ID Validation, Load Bias, and Static Code Correlation.

Tests acceptance criterion 4:
4. Debug-image/build identity mismatch and unresolved symbol/address mapping.
"""

import os
import unittest

from extractor.investigation import InvestigationManager, InvestigationSession
from extractor.modules import RuntimeModule
from extractor.static_analyzer import (
    DwarfStaticAnalysisProvider,
    MockStaticAnalysisProvider,
    NullStaticAnalysisProvider,
    get_static_provider,
)


class TestIdentityMismatchAndStaticAnalysis(unittest.TestCase):
    """Test identity mismatch detection, load bias validation, and static-code linkage."""

    def test_build_id_mismatch_prevents_silent_decode(self):
        # Create module with mismatched Build ID
        module_mismatch = RuntimeModule(
            module_id="app_worker",
            path="/app/prod_worker",
            runtime_base=0x555555554000,
            runtime_end=0x555555560000,
            load_bias=0x555555554000,
            build_id="aabbccdd11223344",
            load_bias_status="RESOLVED",
            build_id_status="MISMATCH",
        )

        mock_provider = MockStaticAnalysisProvider()
        runtime_addr = 0x555555554000 + 0x1140

        res = mock_provider.resolve_runtime_to_code(runtime_addr, module=module_mismatch)
        self.assertEqual(res["status"], "UNRESOLVED_BUILD_ID_MISMATCH")
        self.assertIsNone(res["link_basis"])
        self.assertIn("mismatches debug image", res["reason"])

    def test_unresolved_load_bias_reported_honestly(self):
        # Module where load bias could not be resolved deterministically
        module_unresolved = RuntimeModule(
            module_id="app_worker",
            path="/app/prod_worker",
            runtime_base=0x555555554000,
            runtime_end=0x555555560000,
            load_bias=None,
            build_id="11223344aabbccdd",
            load_bias_status="UNRESOLVED",
            build_id_status="VERIFIED",
        )

        mock_provider = MockStaticAnalysisProvider()
        runtime_addr = 0x555555554000 + 0x1140

        res = mock_provider.resolve_runtime_to_code(runtime_addr, module=module_unresolved)
        self.assertEqual(res["status"], "UNRESOLVED_LOAD_BIAS")
        self.assertIsNone(res["link_basis"])
        self.assertIn("UNRESOLVED load bias", res["reason"])

    def test_defensible_static_code_linkage(self):
        # Valid module with resolved load bias and verified Build ID
        module_ok = RuntimeModule(
            module_id="app_worker",
            path="/app/prod_worker",
            runtime_base=0x555555554000,
            runtime_end=0x555555560000,
            load_bias=0x555555554000,
            build_id="11223344aabbccdd",
            load_bias_status="RESOLVED",
            build_id_status="VERIFIED",
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
            build_id_status="VERIFIED",
        )

        mock_provider = MockStaticAnalysisProvider()
        # Query random address not indexed in functions
        runtime_addr = module_ok.load_bias + 0x9999

        res = mock_provider.resolve_runtime_to_code(runtime_addr, module=module_ok)
        self.assertEqual(res["status"], "UNRESOLVED_ADDRESS_NOT_FOUND")
        self.assertIsNone(res["link_basis"])
        self.assertIn("not found in mock symbols", res["reason"])

    def test_static_provider_pluggability(self):
        dwarf_prov = get_static_provider("dwarf")
        self.assertIsInstance(dwarf_prov, DwarfStaticAnalysisProvider)

        mock_prov = get_static_provider("mock")
        self.assertIsInstance(mock_prov, MockStaticAnalysisProvider)

        null_prov = get_static_provider("null")
        self.assertIsInstance(null_prov, NullStaticAnalysisProvider)

    def test_investigation_manager_handles_build_id_mismatch(self):
        mgr = InvestigationManager()
        session = mgr.start_investigation(
            goal="Investigate memory with mismatched debug image",
            debug_image="/nonexistent/mismatched_debug.elf",
        )
        self.assertIn(session["status"], ("COMPLETED", "PARTIAL", "FAILED"))
        # Identity stage must report debug image status honestly
        ident = session["stages"]["target_identity"]["details"]
        self.assertEqual(ident["build_id_status"], "NOT_AVAILABLE")


if __name__ == "__main__":
    unittest.main()
