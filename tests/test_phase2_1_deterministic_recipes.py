"""Phase 2.1 — Deterministic Diagnostic Recipes Test Suite.

Verifies all 22 expert diagnostic recipes across the 4 domains:
4.1 Memory Integrity (6 recipes)
4.2 Memory Growth and Leaks (6 recipes)
4.3 Abnormal Runtime State (5 recipes)
4.4 Thread and Synchronization (5 recipes)

Tests positive, negative, ambiguous, and insufficient-evidence criteria.
"""

import unittest

from extractor.diagnostic_recipes import (
    BUILTIN_RECIPE_IDS,
    DOMAIN_ABNORMAL_STATE,
    DOMAIN_CONCURRENCY,
    DOMAIN_MEMORY_GROWTH,
    DOMAIN_MEMORY_INTEGRITY,
    RECIPE_ALLOCATION_FREE_IMBALANCE,
    RECIPE_DOUBLE_FREE,
    RECIPE_HEAP_GROWTH,
    RECIPE_HEAP_METADATA_CORRUPTION,
    RECIPE_INCONSISTENT_RELATED_VARIABLES,
    RECIPE_INVALID_FREE,
    RECIPE_INVALID_MEMORY_ACCESS,
    RECIPE_LONG_LIVED_OBJECT_ACCUMULATION,
    RECIPE_LONG_RUNNING_BLOCKED_THREADS,
    RECIPE_OBJECT_LIFETIME_ANOMALIES,
    RECIPE_POTENTIAL_DEADLOCK_PATTERNS,
    RECIPE_PROCESS_MEMORY_GROWTH,
    RECIPE_REPEATED_ALLOCATION_PATTERNS,
    RECIPE_SHARED_STATE_INCONSISTENCIES,
    RECIPE_STATUS_AMBIGUOUS,
    RECIPE_STATUS_CONTRADICTED,
    RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
    RECIPE_STATUS_SUPPORTED,
    RECIPE_SUSPICIOUS_ALLOCATION_PATTERNS,
    RECIPE_SUSPICIOUS_BOUNDARY_VALUES,
    RECIPE_SUSPICIOUS_LOCK_OWNERSHIP,
    RECIPE_THREAD_STATE_ANOMALIES,
    RECIPE_UNEXPECTED_NULL_OR_INVALID_POINTERS,
    RECIPE_UNEXPECTED_VARIABLE_CHANGES,
    RECIPE_USE_AFTER_FREE,
    DiagnosticRecipeRegistry,
)


class TestPhase21DeterministicRecipes(unittest.TestCase):
    """Exhaustive tests for versioned deterministic diagnostic recipes."""

    def setUp(self):
        self.registry = DiagnosticRecipeRegistry()

    def test_all_22_recipes_registered_and_metadata_complete(self):
        """Verifies that all 22 deterministic recipes exist and contain mandatory fields."""
        # IMP-018: the 22 built-in recipes (recipe definition files under extractor/recipe_plugins add more)
        recipes = [self.registry.get_recipe(r) for r in BUILTIN_RECIPE_IDS]
        self.assertEqual(len(recipes), 22, f"Expected 22 recipes, found {len(recipes)}")

        for r in recipes:
            self.assertTrue(r.recipe_id.startswith("RECIPE_"))
            self.assertTrue(len(r.name) > 0)
            self.assertIn(r.domain, [DOMAIN_MEMORY_INTEGRITY, DOMAIN_MEMORY_GROWTH, DOMAIN_ABNORMAL_STATE, DOMAIN_CONCURRENCY])
            self.assertGreater(len(r.applicable_problem_categories), 0)
            self.assertGreater(len(r.required_prerequisites), 0)
            self.assertGreater(len(r.evidence_sources), 0)
            self.assertGreater(len(r.collection_steps), 0)
            self.assertGreater(len(r.analysis_rules), 0)
            self.assertGreater(len(r.thresholds_and_conditions), 0)
            self.assertGreater(len(r.supporting_evidence_criteria), 0)
            self.assertGreater(len(r.contradicting_evidence_criteria), 0)
            self.assertTrue(len(r.verification_procedure) > 0)
            self.assertGreater(len(r.stop_conditions), 0)
            self.assertGreater(len(r.limitations), 0)
            self.assertGreater(len(r.output_structure), 0)

    # -------------------------------------------------------------------------
    # 4.1 Memory Integrity Recipes
    # -------------------------------------------------------------------------

    def test_recipe_invalid_memory_access(self):
        # Positive: fault address in NULL page (< 4096)
        pos = self.registry.evaluate_recipe(RECIPE_INVALID_MEMORY_ACCESS, {
            "fault_address": 0x38,
            "region_permissions": "---p",
        })
        self.assertEqual(pos.status, RECIPE_STATUS_SUPPORTED)
        self.assertGreaterEqual(pos.confidence, 0.90)

        # Negative: valid heap address with readable permissions
        neg = self.registry.evaluate_recipe(RECIPE_INVALID_MEMORY_ACCESS, {
            "fault_address": 0x7fff0000,
            "region_permissions": "rw-p",
        })
        self.assertEqual(neg.status, RECIPE_STATUS_CONTRADICTED)

    def test_recipe_double_free(self):
        # Positive: freed slot freed again
        pos = self.registry.evaluate_recipe(RECIPE_DOUBLE_FREE, {
            "slot_status": "FREE",
            "operation": "FREE",
            "freed_epoch": 1,
            "current_epoch": 2,
        })
        self.assertEqual(pos.status, RECIPE_STATUS_SUPPORTED)
        self.assertGreaterEqual(pos.confidence, 0.90)

        # Negative: active slot freed first time
        neg = self.registry.evaluate_recipe(RECIPE_DOUBLE_FREE, {
            "slot_status": "IN_USE",
            "operation": "FREE",
        })
        self.assertEqual(neg.status, RECIPE_STATUS_CONTRADICTED)

    def test_recipe_invalid_free(self):
        # Positive: free called on stack or static region
        pos = self.registry.evaluate_recipe(RECIPE_INVALID_FREE, {
            "target_address": 0x7fffffffe000,
            "mapped_region": "[stack]",
        })
        self.assertEqual(pos.status, RECIPE_STATUS_SUPPORTED)

        # Negative: free on heap
        neg = self.registry.evaluate_recipe(RECIPE_INVALID_FREE, {
            "target_address": 0x555555600000,
            "mapped_region": "[heap]",
        })
        self.assertEqual(neg.status, RECIPE_STATUS_CONTRADICTED)

    def test_recipe_use_after_free(self):
        # Positive: dereferencing poison pattern 0xdddddddd
        pos = self.registry.evaluate_recipe(RECIPE_USE_AFTER_FREE, {
            "access_address": 0x555555600100,
            "target_slot_status": "FREE",
            "memory_content_hex": "dddddddddddddddd",
        })
        self.assertEqual(pos.status, RECIPE_STATUS_SUPPORTED)

        # Negative: valid memory in use
        neg = self.registry.evaluate_recipe(RECIPE_USE_AFTER_FREE, {
            "access_address": 0x555555600100,
            "target_slot_status": "IN_USE",
            "memory_content_hex": "0100000000000000",
        })
        self.assertEqual(neg.status, RECIPE_STATUS_CONTRADICTED)

    def test_recipe_heap_metadata_corruption(self):
        # Positive: chunk header corrupted
        pos = self.registry.evaluate_recipe(RECIPE_HEAP_METADATA_CORRUPTION, {
            "chunk_size": 0xFFFFFFFFFFFFFFFF,
            "canary_valid": False,
        })
        self.assertEqual(pos.status, RECIPE_STATUS_SUPPORTED)

        # Negative: valid canary and chunk size
        neg = self.registry.evaluate_recipe(RECIPE_HEAP_METADATA_CORRUPTION, {
            "chunk_size": 256,
            "canary_valid": True,
        })
        self.assertEqual(neg.status, RECIPE_STATUS_CONTRADICTED)

    def test_recipe_suspicious_allocation_patterns(self):
        # Positive: gigantic allocation request
        pos = self.registry.evaluate_recipe(RECIPE_SUSPICIOUS_ALLOCATION_PATTERNS, {
            "requested_bytes": 1024 * 1024 * 1024 * 16,  # 16GB
        })
        self.assertEqual(pos.status, RECIPE_STATUS_SUPPORTED)

    # -------------------------------------------------------------------------
    # 4.2 Memory Growth and Leak Recipes
    # -------------------------------------------------------------------------

    def test_recipe_process_memory_growth(self):
        # Positive: monotonic RSS growth over 3 epochs
        pos = self.registry.evaluate_recipe(RECIPE_PROCESS_MEMORY_GROWTH, {
            "rss_history_kb": [10000, 15000, 22000, 30000],
            "epoch_count": 4,
        })
        self.assertEqual(pos.status, RECIPE_STATUS_SUPPORTED)

        # Ambiguous: 2 epochs only
        amb = self.registry.evaluate_recipe(RECIPE_PROCESS_MEMORY_GROWTH, {
            "rss_history_kb": [10000, 15000],
            "epoch_count": 2,
        })
        self.assertEqual(amb.status, RECIPE_STATUS_AMBIGUOUS)

        # Negative: stable RSS
        neg = self.registry.evaluate_recipe(RECIPE_PROCESS_MEMORY_GROWTH, {
            "rss_history_kb": [10000, 10020, 10010, 10015],
            "epoch_count": 4,
        })
        self.assertEqual(neg.status, RECIPE_STATUS_CONTRADICTED)

    def test_recipe_allocation_free_imbalance(self):
        # Positive: 1000 allocs, 20 frees -> high ratio
        pos = self.registry.evaluate_recipe(RECIPE_ALLOCATION_FREE_IMBALANCE, {
            "alloc_count": 1000,
            "free_count": 20,
        })
        self.assertEqual(pos.status, RECIPE_STATUS_SUPPORTED)

        # Negative: 1000 allocs, 998 frees
        neg = self.registry.evaluate_recipe(RECIPE_ALLOCATION_FREE_IMBALANCE, {
            "alloc_count": 1000,
            "free_count": 998,
        })
        self.assertEqual(neg.status, RECIPE_STATUS_CONTRADICTED)

    # -------------------------------------------------------------------------
    # 4.3 Abnormal Runtime State Recipes
    # -------------------------------------------------------------------------

    def test_recipe_unexpected_variable_changes(self):
        # Positive: state jumped from 1 to 999
        pos = self.registry.evaluate_recipe(RECIPE_UNEXPECTED_VARIABLE_CHANGES, {
            "variable_name": "g_worker_state",
            "previous_val": 1,
            "current_val": 999,
            "valid_range": (0, 10),
        })
        self.assertEqual(pos.status, RECIPE_STATUS_SUPPORTED)

        # Negative: state within range
        neg = self.registry.evaluate_recipe(RECIPE_UNEXPECTED_VARIABLE_CHANGES, {
            "variable_name": "g_worker_state",
            "previous_val": 1,
            "current_val": 2,
            "valid_range": (0, 10),
        })
        self.assertEqual(neg.status, RECIPE_STATUS_CONTRADICTED)

    def test_recipe_suspicious_boundary_values(self):
        # Positive: integer overflow near 0xFFFFFFFF
        pos = self.registry.evaluate_recipe(RECIPE_SUSPICIOUS_BOUNDARY_VALUES, {
            "variable_name": "buffer_len",
            "value": 0xFFFFFFFF,
            "type": "uint32_t",
        })
        self.assertEqual(pos.status, RECIPE_STATUS_SUPPORTED)

    # -------------------------------------------------------------------------
    # 4.4 Thread and Synchronization Recipes
    # -------------------------------------------------------------------------

    def test_recipe_potential_deadlock_patterns(self):
        # Positive: circular lock dependency
        pos = self.registry.evaluate_recipe(RECIPE_POTENTIAL_DEADLOCK_PATTERNS, {
            "thread_locks": {
                101: {"holding": ["mutex_A"], "waiting_for": "mutex_B"},
                102: {"holding": ["mutex_B"], "waiting_for": "mutex_A"},
            },
            "cycle_persistent": True,
            "observation_count": 2,
        })
        self.assertEqual(pos.status, RECIPE_STATUS_SUPPORTED)
        self.assertGreaterEqual(pos.confidence, 0.95)

        # Negative: no circular wait
        neg = self.registry.evaluate_recipe(RECIPE_POTENTIAL_DEADLOCK_PATTERNS, {
            "thread_locks": {
                101: {"holding": ["mutex_A"], "waiting_for": None},
                102: {"holding": [], "waiting_for": "mutex_A"},
            }
        })
        self.assertEqual(neg.status, RECIPE_STATUS_CONTRADICTED)

    def test_recipe_insufficient_evidence_when_missing_data(self):
        """Verifies INSUFFICIENT_EVIDENCE is reported when required fields or prerequisites are absent."""
        res = self.registry.evaluate_recipe(RECIPE_POTENTIAL_DEADLOCK_PATTERNS, {})
        self.assertEqual(res.status, RECIPE_STATUS_INSUFFICIENT_EVIDENCE)
        self.assertTrue(len(res.missing_evidence) > 0)


if __name__ == "__main__":
    unittest.main()
