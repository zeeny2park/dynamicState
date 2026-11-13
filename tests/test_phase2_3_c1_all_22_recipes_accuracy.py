"""Phase 2.3-C.1: Accuracy & Diagnostic Semantics Validation for All 22 Recipes.

Validates P0 requirements:
- Enumerates all 22 registered recipes in DiagnosticRecipeRegistry.
- Asserts authentic diagnostic accuracy (defect detection vs healthy refutation):
  * Healthy Target: Recipe refutes defect (CONTRADICTED / healthy PASS). No false positives.
  * Defective Target: Recipe detects defect (SUPPORTED / defect FAIL). No false negatives.
  * Insufficient Evidence: Explicitly returns INSUFFICIENT_EVIDENCE or NOT_APPLICABLE.
  * Inapplicable / Missing Prerequisites: Explicitly returns NOT_APPLICABLE / INSUFFICIENT_EVIDENCE.
- Exercises live compiled C/C++ processes with authentic DWARF symbol evaluation and memory inspection.
"""

import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest

from extractor.diagnostic_recipes import (
    BUILTIN_RECIPE_IDS,
    DiagnosticRecipeRegistry,
    RECIPE_STATUS_SUPPORTED,
    RECIPE_STATUS_CONTRADICTED,
    RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
    RECIPE_STATUS_NOT_APPLICABLE,
)
from extractor.expert_diagnostic_engine import ExpertDiagnosticEngine
from tests.support.fixture_process import fixture_popen


CPP_CONTROLLED_TARGET_SRC = """
#include <iostream>
#include <thread>
#include <chrono>
#include <vector>
#include <string>
#include <mutex>
#include <cstring>

// Control variable: 0 = Healthy, 1 = Defect Mode
volatile int g_target_mode = 0;

// Variables for Memory Integrity recipes
unsigned int g_canary_magic = 0x11223344; // Healthy
int* g_safe_pointer = nullptr;
int g_pointed_value = 42;

// Variables for Abnormal State recipes
int g_state_machine_val = 1; // Valid states: 0, 1, 2
int g_buffer_capacity = 100;
int g_buffer_length = 20;

// Variables for Concurrency recipes
std::mutex g_mutex_a;
int g_shared_val_1 = 10;
int g_shared_val_2 = 20;

int main(int argc, char** argv) {
    g_safe_pointer = &g_pointed_value;

    if (argc > 1 && strcmp(argv[1], "--defect") == 0) {
        g_target_mode = 1;
        g_canary_magic = 0xDEADBEEF; // Injected corruption
        g_state_machine_val = 999;   // Injected state violation
        g_buffer_length = 500;       // Injected inconsistency: length > capacity
    }

    std::cout << "READY_PID=" << std::endl;
    std::cout.flush();

    while (true) {
        {
            std::lock_guard<std::mutex> lock(g_mutex_a);
            g_pointed_value++;
            if (g_target_mode == 0) {
                g_shared_val_1++;
                g_shared_val_2 = g_shared_val_1 * 2;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return 0;
}
"""


class TestPhase23C1All22RecipesAccuracy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp(prefix="phase2_3_c1_recipes_")
        cls.src_path = os.path.join(cls.tmpdir, "target.cpp")
        cls.bin_healthy = os.path.join(cls.tmpdir, "target_healthy")
        cls.bin_defect = os.path.join(cls.tmpdir, "target_defect")

        with open(cls.src_path, "w", encoding="utf-8") as f:
            f.write(CPP_CONTROLLED_TARGET_SRC)

        subprocess.check_call(["g++", "-g", "-O0", "-pthread", cls.src_path, "-o", cls.bin_healthy])
        subprocess.check_call(["g++", "-g", "-O0", "-pthread", cls.src_path, "-o", cls.bin_defect])

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def _start_proc(self, bin_path: str, args=None):
        cmd = [bin_path] + (args or [])
        proc = fixture_popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        line = proc.stdout.readline()
        self.assertIn("READY_PID=", line)
        return proc

    def _stop_proc(self, proc):
        if proc.stdout:
            proc.stdout.close()
        if proc.stderr:
            proc.stderr.close()
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

    def test_enumerate_all_22_recipes_complete_registry(self):
        """Registry contains exactly the 22 canonical recipes with complete specifications."""
        recipe_ids = list(BUILTIN_RECIPE_IDS)
        self.assertEqual(len(recipe_ids), 22)
        for rid in recipe_ids:
            r = DiagnosticRecipeRegistry.get_recipe(rid)
            self.assertIsNotNone(r)
            self.assertTrue(r.recipe_id.startswith("RECIPE_"))
            self.assertIn(r.domain, ("MEMORY_INTEGRITY", "MEMORY_GROWTH", "ABNORMAL_STATE", "CONCURRENCY"))
            self.assertGreater(len(r.required_prerequisites), 0)

    def test_all_22_recipes_deterministic_defect_detection(self):
        """Every recipe correctly detects its defect when injected into observation data."""
        registry = DiagnosticRecipeRegistry()

        defect_observations = {
            "RECIPE_INVALID_MEMORY_ACCESS": {"address": 0x0, "is_mapped": False, "violation_type": "NULL_POINTER_DEREFERENCE"},
            "RECIPE_DOUBLE_FREE": {"double_free_recorded": True, "operation": "FREE"},
            "RECIPE_INVALID_FREE": {"aligned": False, "vma_name": "[stack]"},
            "RECIPE_USE_AFTER_FREE": {"in_freelist": True, "poison_detected": True},
            "RECIPE_HEAP_METADATA_CORRUPTION": {"magic_corrupted": True, "canary_corrupted": True},
            "RECIPE_SUSPICIOUS_ALLOCATION_PATTERNS": {"requested_bytes": 2147483648},
            "RECIPE_PROCESS_MEMORY_GROWTH": {"is_monotonic": True, "rss_growth_bytes": 1048576, "epoch_count": 4, "rss_history_kb": [1000, 1500, 2000, 2500]},
            "RECIPE_HEAP_GROWTH": {"heap_growth_bytes": 524288, "heap_series_kb": [1024, 1536, 2048], "epoch_count": 3},
            "RECIPE_ALLOCATION_FREE_IMBALANCE": {"alloc_count": 1000, "free_count": 50},
            "RECIPE_OBJECT_LIFETIME_ANOMALIES": {"lifetime_expired": True},
            "RECIPE_REPEATED_ALLOCATION_PATTERNS": {"unreclaimed_site_growth": True},
            "RECIPE_LONG_LIVED_OBJECT_ACCUMULATION": {"object_count_delta": 5000, "is_accumulating": True, "monotonic_growth": True, "delta_bytes": 1048576},
            "RECIPE_UNEXPECTED_VARIABLE_CHANGES": {"current_val": 999, "valid_range": [0, 100]},
            "RECIPE_STATE_TRANSITION_VIOLATIONS": {"allowed_states": [0, 1, 2], "current_state": 999, "state_specification": "spec1"},
            "RECIPE_INCONSISTENT_RELATED_VARIABLES": {"buffer_capacity": 100, "buffer_length": 500},
            "RECIPE_UNEXPECTED_NULL_OR_INVALID_POINTERS": {"pointer_value": "0x0", "is_null_allowed": False, "is_active_lifecycle": True},
            "RECIPE_SUSPICIOUS_BOUNDARY_VALUES": {"value": 0x7FFFFFFF},
            "RECIPE_THREAD_STATE_ANOMALIES": {"zombie_threads": True},
            "RECIPE_SUSPICIOUS_LOCK_OWNERSHIP": {"orphan_lock_owner": True},
            "RECIPE_POTENTIAL_DEADLOCK_PATTERNS": {"cycle_detected": True, "is_persistent": True, "historical_observations": 3},
            "RECIPE_LONG_RUNNING_BLOCKED_THREADS": {"blocked_threads": [101], "blocked_duration_sec": 5.0},
            "RECIPE_SHARED_STATE_INCONSISTENCIES": {"shared_invariant_violated": True},
        }

        for rid in list(BUILTIN_RECIPE_IDS):
            with self.subTest(recipe_id=rid):
                obs = defect_observations.get(rid, {"positive_evidence_found": True})
                res = registry.evaluate_recipe(rid, obs, prerequisites_met=True)
                self.assertEqual(
                    res.status,
                    RECIPE_STATUS_SUPPORTED,
                    f"Recipe {rid} failed to detect injected defect; returned {res.status}: {res.confidence_basis}",
                )
                self.assertGreater(res.confidence, 0.5)
                self.assertGreater(len(res.supporting_facts), 0)

    def test_all_22_recipes_deterministic_healthy_refutation(self):
        """Every recipe refutes defect when healthy data is observed (no false positives)."""
        registry = DiagnosticRecipeRegistry()

        healthy_observations = {
            "RECIPE_INVALID_MEMORY_ACCESS": {"violation_type": "NONE", "is_healthy": True},
            "RECIPE_DOUBLE_FREE": {"freelist_occurrences": 0, "prev_inuse": 1},
            "RECIPE_INVALID_FREE": {"aligned": True, "vma_name": "[heap]"},
            "RECIPE_USE_AFTER_FREE": {"is_active_chunk": True, "in_freelist": False, "poison_detected": False},
            "RECIPE_HEAP_METADATA_CORRUPTION": {"canary_valid": True},
            "RECIPE_SUSPICIOUS_ALLOCATION_PATTERNS": {"negative_evidence_found": True},
            "RECIPE_PROCESS_MEMORY_GROWTH": {"is_monotonic": False, "rss_growth_bytes": 0, "epoch_count": 3, "rss_history_kb": [1000, 1000, 1000]},
            "RECIPE_HEAP_GROWTH": {"heap_growth_bytes": 0, "heap_series_kb": [1024, 1024]},
            "RECIPE_ALLOCATION_FREE_IMBALANCE": {"alloc_count": 500, "free_count": 500},
            "RECIPE_OBJECT_LIFETIME_ANOMALIES": {"lifetime_valid": True},
            "RECIPE_REPEATED_ALLOCATION_PATTERNS": {"alloc_reclaimed": True},
            "RECIPE_LONG_LIVED_OBJECT_ACCUMULATION": {"object_count_delta": 2},
            "RECIPE_UNEXPECTED_VARIABLE_CHANGES": {"current_val": 50, "valid_range": [0, 100]},
            "RECIPE_STATE_TRANSITION_VIOLATIONS": {"allowed_states": [0, 1, 2], "current_state": 1, "is_illegal_transition": False, "state_specification": "spec1"},
            "RECIPE_INCONSISTENT_RELATED_VARIABLES": {"buffer_capacity": 100, "buffer_length": 20},
            "RECIPE_UNEXPECTED_NULL_OR_INVALID_POINTERS": {"pointer_value": "0x1000", "is_mapped": True},
            "RECIPE_SUSPICIOUS_BOUNDARY_VALUES": {"value": 42, "negative_evidence_found": True},
            "RECIPE_THREAD_STATE_ANOMALIES": {"threads_healthy": True},
            "RECIPE_SUSPICIOUS_LOCK_OWNERSHIP": {"callstacks_info": {"threads": []}, "orphan_lock_owner": False, "deadlock_detected": False},
            "RECIPE_POTENTIAL_DEADLOCK_PATTERNS": {"thread_locks": {"1": {"holding": ["L1"]}}, "cycle_detected": False},
            "RECIPE_LONG_RUNNING_BLOCKED_THREADS": {"blocked_threads": []},
            "RECIPE_SHARED_STATE_INCONSISTENCIES": {"shared_invariant_intact": True},
        }

        for rid in list(BUILTIN_RECIPE_IDS):
            with self.subTest(recipe_id=rid):
                obs = healthy_observations.get(rid, {"negative_evidence_found": True})
                res = registry.evaluate_recipe(rid, obs, prerequisites_met=True)
                self.assertEqual(
                    res.status,
                    RECIPE_STATUS_CONTRADICTED,
                    f"Recipe {rid} falsely reported anomaly on healthy data; returned {res.status}",
                )
                self.assertGreater(res.confidence, 0.5)
                self.assertGreater(len(res.contradicting_facts), 0)

    def test_all_22_recipes_insufficient_evidence_behavior(self):
        """When observation data is empty, recipe returns INSUFFICIENT_EVIDENCE or NOT_APPLICABLE."""
        registry = DiagnosticRecipeRegistry()

        for rid in list(BUILTIN_RECIPE_IDS):
            with self.subTest(recipe_id=rid):
                res = registry.evaluate_recipe(rid, {}, prerequisites_met=True)
                self.assertIn(
                    res.status,
                    (RECIPE_STATUS_INSUFFICIENT_EVIDENCE, RECIPE_STATUS_NOT_APPLICABLE),
                    f"Recipe {rid} must return INSUFFICIENT_EVIDENCE/NOT_APPLICABLE on empty observation data, got {res.status}",
                )
                self.assertTrue(len(res.missing_evidence) > 0 or res.not_applicable_reason is not None)

    def test_all_22_recipes_unsupported_prerequisite_behavior(self):
        """When prerequisites are not met, recipe explicitly returns INSUFFICIENT_EVIDENCE with missing prerequisites."""
        registry = DiagnosticRecipeRegistry()

        for rid in list(BUILTIN_RECIPE_IDS):
            with self.subTest(recipe_id=rid):
                res = registry.evaluate_recipe(rid, {"prerequisites_missing": True}, prerequisites_met=False)
                self.assertEqual(res.status, RECIPE_STATUS_INSUFFICIENT_EVIDENCE)
                self.assertGreater(len(res.missing_evidence), 0)
                self.assertIn("prerequisites", res.confidence_basis.lower())

    def test_live_compiled_healthy_vs_defect_target_execution(self):
        """Evaluates live compiled processes to verify end-to-end defect detection on real memory."""
        proc_healthy = self._start_proc(self.bin_healthy)
        proc_defect = self._start_proc(self.bin_defect, args=["--defect"])

        engine = ExpertDiagnosticEngine(corpus_dir=self.tmpdir)
        try:
            # 1. State transition violation recipe on defect target with specification -> MUST DETECT
            res_defect = engine.run_recipe(
                recipe_id="RECIPE_STATE_TRANSITION_VIOLATIONS",
                pid=proc_defect.pid,
                companion_elf=self.bin_defect,
                expressions=["g_state_machine_val"],
                thresholds={"state_specification": "spec_mode", "allowed_states": [0, 1, 2]},
            )
            check_defect = res_defect["checks"][0]
            self.assertEqual(check_defect["status"], "FAIL")
            self.assertEqual(res_defect["status"], "FAIL")

            # 2. Consistent related variables on defect target -> MUST DETECT (buffer length 500 > capacity 100)
            res_pairs_defect = engine.run_recipe(
                recipe_id="RECIPE_INCONSISTENT_RELATED_VARIABLES",
                pid=proc_defect.pid,
                companion_elf=self.bin_defect,
                expressions=["g_buffer_capacity", "g_buffer_length"],
            )
            check_pairs = res_pairs_defect["checks"][0]
            self.assertEqual(check_pairs["status"], "FAIL")

            # 3. Healthy target with same expressions -> MUST PASS (buffer length 20 <= capacity 100)
            res_pairs_healthy = engine.run_recipe(
                recipe_id="RECIPE_INCONSISTENT_RELATED_VARIABLES",
                pid=proc_healthy.pid,
                companion_elf=self.bin_healthy,
                expressions=["g_buffer_capacity", "g_buffer_length"],
            )
            check_healthy = res_pairs_healthy["checks"][0]
            self.assertEqual(check_healthy["status"], "PASS")

        finally:
            self._stop_proc(proc_healthy)
            self._stop_proc(proc_defect)


if __name__ == "__main__":
    unittest.main()
