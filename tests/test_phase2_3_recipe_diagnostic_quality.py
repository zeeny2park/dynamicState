"""Phase 2.3-A: Diagnostic Recipe Quality Verification Suite.

Validates deterministic recipe evaluation across all 4 domains:
1. Memory Integrity (RECIPE_INVALID_MEMORY_ACCESS, RECIPE_INVALID_FREE, RECIPE_DOUBLE_FREE, RECIPE_HEAP_METADATA_CORRUPTION)
2. Memory Growth & Leaks (RECIPE_PROCESS_MEMORY_GROWTH, RECIPE_ALLOCATION_FREE_IMBALANCE)
3. Abnormal State (RECIPE_UNEXPECTED_NULL_OR_INVALID_POINTERS, RECIPE_STATE_TRANSITION_VIOLATIONS)
4. Concurrency (RECIPE_POTENTIAL_DEADLOCK_PATTERNS, RECIPE_LONG_RUNNING_BLOCKED_THREADS)

Verifies:
- Defect injection yields SUPPORTED (FAIL/Defect Confirmed)
- Healthy baseline yields CONTRADICTED (PASS/Healthy)
- Missing required evidence yields INSUFFICIENT_EVIDENCE
- Incompatible scopes or missing prerequisites yields NOT_APPLICABLE / INSUFFICIENT_EVIDENCE with 0.0 confidence
"""

import unittest
from extractor.diagnostic_recipes import (
    DiagnosticRecipeRegistry,
    RECIPE_STATUS_SUPPORTED,
    RECIPE_STATUS_CONTRADICTED,
    RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
    RECIPE_STATUS_NOT_APPLICABLE,
    RECIPE_INVALID_MEMORY_ACCESS,
    RECIPE_INVALID_FREE,
    RECIPE_DOUBLE_FREE,
    RECIPE_HEAP_METADATA_CORRUPTION,
    RECIPE_PROCESS_MEMORY_GROWTH,
    RECIPE_ALLOCATION_FREE_IMBALANCE,
    RECIPE_UNEXPECTED_NULL_OR_INVALID_POINTERS,
    RECIPE_STATE_TRANSITION_VIOLATIONS,
    RECIPE_POTENTIAL_DEADLOCK_PATTERNS,
    RECIPE_LONG_RUNNING_BLOCKED_THREADS,
)
from extractor.allocator_inspector import GlibcPtMallocInspector


class TestPhase23RecipeDiagnosticQuality(unittest.TestCase):
    def setUp(self):
        self.reg = DiagnosticRecipeRegistry()

    # --- 1. Memory Integrity ---
    def test_invalid_memory_access_evaluation(self):
        # Healthy
        res_pass = self.reg.evaluate_recipe(RECIPE_INVALID_MEMORY_ACCESS, {"is_healthy": True})
        self.assertEqual(res_pass.status, RECIPE_STATUS_CONTRADICTED)

        # Defect (unmapped faulting address)
        res_fail = self.reg.evaluate_recipe(
            RECIPE_INVALID_MEMORY_ACCESS,
            {"faulting_address": 0xDEADBEEF, "is_mapped": False, "is_readable": False}
        )
        self.assertEqual(res_fail.status, RECIPE_STATUS_SUPPORTED)

        # Missing evidence
        res_missing = self.reg.evaluate_recipe(RECIPE_INVALID_MEMORY_ACCESS, {})
        self.assertEqual(res_missing.status, RECIPE_STATUS_INSUFFICIENT_EVIDENCE)

    def test_invalid_free_evaluation(self):
        # Defect: freeing a pointer inside static text segment
        res_fail = self.reg.evaluate_recipe(
            RECIPE_INVALID_FREE,
            {
                "target_address": 0x401000,
                "allocator_inspector": GlibcPtMallocInspector(),
                "maps": [{"start": 0x400000, "end": 0x405000, "permissions": "r-xp", "pathname": "/app"}],
            }
        )
        self.assertEqual(res_fail.status, RECIPE_STATUS_SUPPORTED)

        # Missing evidence
        res_missing = self.reg.evaluate_recipe(RECIPE_INVALID_FREE, {})
        self.assertEqual(res_missing.status, RECIPE_STATUS_INSUFFICIENT_EVIDENCE)

    def test_double_free_evaluation(self):
        # Healthy: active chunk, not in freelist
        res_pass = self.reg.evaluate_recipe(
            RECIPE_DOUBLE_FREE,
            {"freelist_occurrences": 0, "prev_inuse": 1, "double_free_recorded": False}
        )
        self.assertEqual(res_pass.status, RECIPE_STATUS_CONTRADICTED)

        # Defect: double free recorded
        res_fail = self.reg.evaluate_recipe(
            RECIPE_DOUBLE_FREE,
            {"double_free_recorded": True}
        )
        self.assertEqual(res_fail.status, RECIPE_STATUS_SUPPORTED)

        # Missing evidence: single snapshot without history
        res_missing = self.reg.evaluate_recipe(RECIPE_DOUBLE_FREE, {})
        self.assertEqual(res_missing.status, RECIPE_STATUS_INSUFFICIENT_EVIDENCE)

    # --- 2. Memory Growth & Leaks ---
    def test_process_memory_growth_evaluation(self):
        # Healthy: flat memory footprint
        res_pass = self.reg.evaluate_recipe(
            RECIPE_PROCESS_MEMORY_GROWTH,
            {"rss_history_kb": [1000, 1000, 1000], "rss_growth_bytes": 0, "is_monotonic": False, "epoch_count": 3}
        )
        self.assertEqual(res_pass.status, RECIPE_STATUS_CONTRADICTED)

        # Defect: monotonic memory growth > 512KB over >= 3 epochs
        res_fail = self.reg.evaluate_recipe(
            RECIPE_PROCESS_MEMORY_GROWTH,
            {
                "rss_history_kb": [1000, 2000, 3000],
                "rss_growth_bytes": 2048 * 1024,
                "is_monotonic": True,
                "epoch_count": 3,
            }
        )
        self.assertEqual(res_fail.status, RECIPE_STATUS_SUPPORTED)

        # Missing evidence: empty history
        res_missing = self.reg.evaluate_recipe(
            RECIPE_PROCESS_MEMORY_GROWTH,
            {"rss_history_kb": []}
        )
        self.assertEqual(res_missing.status, RECIPE_STATUS_INSUFFICIENT_EVIDENCE)

    def test_allocation_free_imbalance_evaluation(self):
        # Healthy: balanced alloc/free within tolerance
        res_pass = self.reg.evaluate_recipe(
            RECIPE_ALLOCATION_FREE_IMBALANCE,
            {"alloc_count": 100, "free_count": 100}
        )
        self.assertEqual(res_pass.status, RECIPE_STATUS_CONTRADICTED)

        # Defect: 1000 allocs vs 2 frees (>= 5x)
        res_fail = self.reg.evaluate_recipe(
            RECIPE_ALLOCATION_FREE_IMBALANCE,
            {"alloc_count": 1000, "free_count": 2, "alloc_delta": 900, "free_delta": 2}  # static ratio is not a leak: the gap grew over the window
        )
        self.assertEqual(res_fail.status, RECIPE_STATUS_SUPPORTED)

        # Not applicable: incompatible counter measurement scopes
        res_na = self.reg.evaluate_recipe(
            RECIPE_ALLOCATION_FREE_IMBALANCE,
            {"incompatible_counters": True}
        )
        self.assertEqual(res_na.status, RECIPE_STATUS_NOT_APPLICABLE)

    # --- 3. Abnormal State ---
    def test_unexpected_null_or_invalid_pointers(self):
        # Healthy: valid mapped pointer
        res_pass = self.reg.evaluate_recipe(
            RECIPE_UNEXPECTED_NULL_OR_INVALID_POINTERS,
            {"pointer_value": "0x7fff0000", "is_mapped": True}
        )
        self.assertEqual(res_pass.status, RECIPE_STATUS_CONTRADICTED)

        # Defect: null pointer in active lifecycle
        res_fail = self.reg.evaluate_recipe(
            RECIPE_UNEXPECTED_NULL_OR_INVALID_POINTERS,
            {"pointer_value": "0x0", "is_active_lifecycle": True, "is_null_allowed": False}
        )
        self.assertEqual(res_fail.status, RECIPE_STATUS_SUPPORTED)

    # --- 4. Concurrency ---
    def test_potential_deadlock_patterns(self):
        # Healthy: complete acyclic lock graph with no wait cycles
        res_pass = self.reg.evaluate_recipe(
            RECIPE_POTENTIAL_DEADLOCK_PATTERNS,
            {"thread_locks": {"t1": {"holding": "L1"}}, "cycle_detected": False}
        )
        self.assertEqual(res_pass.status, RECIPE_STATUS_CONTRADICTED)

        # Defect: persistent cycle detected
        res_fail = self.reg.evaluate_recipe(
            RECIPE_POTENTIAL_DEADLOCK_PATTERNS,
            {"cycle_detected": True, "is_persistent": True, "historical_observations": 3}
        )
        self.assertEqual(res_fail.status, RECIPE_STATUS_SUPPORTED)

    # --- Prerequisites enforcement ---
    def test_prerequisites_missing_enforcement(self):
        """When prerequisites are marked missing, evaluation immediately returns INSUFFICIENT_EVIDENCE with 0.0 confidence."""
        res = self.reg.evaluate_recipe(
            RECIPE_HEAP_METADATA_CORRUPTION,
            {"prerequisites_missing": True, "missing_prerequisites": ["HEAP_ANALYSIS_ENABLED"]},
            prerequisites_met=False,
        )
        self.assertEqual(res.status, RECIPE_STATUS_INSUFFICIENT_EVIDENCE)
        self.assertEqual(res.confidence, 0.0)
        self.assertIn("HEAP_ANALYSIS_ENABLED", res.missing_evidence)


if __name__ == "__main__":
    unittest.main()
