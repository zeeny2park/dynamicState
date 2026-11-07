"""Phase 2.1 — Evidence-to-Source Correlation Pipeline Tests.

Verifies the 7-step evidence-to-source mapping pipeline:
Observation -> Memory address/object -> C++ type and field -> DWARF information ->
Source file/line -> Function candidates -> Hypothesis -> Verification.
"""

import os
import unittest

from extractor.expert_diagnostic_engine import (
    EvidenceToSourceCorrelator,
    demangle_symbol,
)


class TestPhase21EvidenceSourceCorrelation(unittest.TestCase):
    """Test suite for evidence-to-source correlation pipeline."""

    def setUp(self):
        self.companion_elf = "/tmp/expert_diagnostic_debug.elf"
        self.correlator = EvidenceToSourceCorrelator(companion_elf=self.companion_elf)

    def test_cpp_symbol_demangling(self):
        """Verifies demangling of C++ symbols."""
        mangled_symbols = [
            ("_ZN6Worker3runEv", "Worker::run()"),
            ("_Z25trigger_memory_corruptionv", "trigger_memory_corruption()"),
            ("_Z19trigger_memory_leakv", "trigger_memory_leak()"),
            ("_Z22trigger_abnormal_statev", "trigger_abnormal_state()"),
            ("_Z17thread_deadlock_av", "thread_deadlock_a()"),
        ]
        for mangled, expected_substring in mangled_symbols:
            demangled = demangle_symbol(mangled)
            self.assertIn(expected_substring.split("(")[0], demangled)

    def test_demangle_unmangled_or_c_symbol(self):
        """Verifies unmangled C symbols remain unchanged."""
        c_symbols = ["main", "malloc", "free", "printf", "g_heartbeat"]
        for sym in c_symbols:
            self.assertEqual(demangle_symbol(sym), sym)

    def test_correlate_observation_with_source_location(self):
        """Verifies full correlation of an observation to DWARF symbol and source code context."""
        fixture_source = os.path.abspath("tests/fixtures/real_runtime/expert_diagnostic_scenarios.cpp")
        raw_observation = {
            "address": 0x401200,
            "symbol": "_Z25trigger_memory_corruptionv",
            "type": "WorkerNode",
            "value": "magic=0xDEADBEEF",
            "file": fixture_source,
            "line": 42,
        }

        correlated = self.correlator.correlate(raw_observation)
        self.assertEqual(correlated["address"], 0x401200)
        self.assertIn("trigger_memory_corruption", correlated["demangled_symbol"])
        self.assertEqual(correlated["inferred_type"], "WorkerNode")
        self.assertEqual(correlated["source_file"], fixture_source)
        self.assertEqual(correlated["source_line"], 42)
        self.assertTrue(len(correlated["source_context"]) > 0)
        # Verify current line is marked with '>>' in source context
        self.assertTrue(any(">>" in line for line in correlated["source_context"]))
        self.assertIn(correlated["demangled_symbol"], correlated["function_candidates"])

    def test_correlate_observation_missing_dwarf_graceful_fallback(self):
        """Verifies correlation handles missing companion ELF or unresolvable address gracefully."""
        correlator_empty = EvidenceToSourceCorrelator(companion_elf="/nonexistent/app.elf")
        raw_observation = {
            "address": 0x7ffff7a00000,
            "symbol": "g_heartbeat",
            "type": "volatile int",
            "value": 42,
        }
        res = correlator_empty.correlate(raw_observation)
        self.assertEqual(res["address"], 0x7ffff7a00000)
        self.assertEqual(res["demangled_symbol"], "g_heartbeat")
        self.assertIsNone(res["source_file"])
        self.assertIsNone(res["source_line"])
        self.assertEqual(res["source_context"], [])


if __name__ == "__main__":
    unittest.main()
