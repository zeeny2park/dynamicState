"""
Phase 2.1.3 Validation Test Suite
Tests for Expert Diagnostic Semantics & Investigation Intelligence across Cases A through P.
"""

import os
import unittest
from unittest.mock import patch
from typing import Dict, Any, List

from extractor.diagnostic_rule_model import (
    DiagnosticRule,
    RuleApplicabilityResult,
    RECIPE_STATUS_NOT_APPLICABLE,
    VERDICT_CONFIRMED,
    VERDICT_LIKELY,
    VERDICT_REFUTED,
    VERDICT_INCONCLUSIVE,
    VERDICT_NOT_APPLICABLE,
)
from extractor.diagnostic_recipes import (
    DiagnosticRecipeRegistry,
    RecipeEvaluationResult,
    RECIPE_STATUS_SUPPORTED,
    RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
    RECIPE_STATUS_CONTRADICTED,
    RECIPE_STATUS_NOT_APPLICABLE,
)
from extractor.allocator_inspector import (
    detect_allocator,
    GlibcPtMallocInspector,
    JemallocInspector,
    TcmallocInspector,
    UnknownAllocatorInspector,
)
from extractor.temporal_observation_window import (
    ObservationWindow,
    MemorySample,
    MemoryBehavior,
)
from extractor.cpp_structural_discovery import (
    CppStructuralDiscovery,
    CppRelationshipType,
    ExpertOverrideConstraint,
)
from extractor.invariant_framework import (
    InvariantEvaluator,
    InvariantDefinition,
    InvariantType,
    InvariantSource,
)
from extractor.concurrency_graph import (
    WaitForGraph,
    ThreadNode,
    LockNode,
    WaitingEdge,
    OwnershipEdge,
    UnresolvedOwnershipEdge,
    ConcurrencyState,
)
from extractor.competing_hypotheses import (
    CompetingHypothesis,
    CompetingHypothesisManager,
)
from extractor.expert_diagnostic_engine import (
    ExpertDiagnosticEngine,
    AdaptiveInvestigationSession,
    InvestigationStep,
)


class TestPhase213DiagnosticSemantics(unittest.TestCase):
    def setUp(self):
        self.registry = DiagnosticRecipeRegistry()

    # Case A: Low pointer address without dereference != access fault
    def test_case_a_low_pointer_without_dereference(self):
        # Context with low pointer (address=0x10), but dereference_attempted=False
        context = {
            "pointer_address": 0x10,
            "dereference_attempted": False,
            "maps": [{"start": 0x400000, "end": 0x450000, "perms": "r-xp"}],
        }
        res = self.registry.evaluate_recipe("RECIPE_INVALID_MEMORY_ACCESS", context)
        self.assertEqual(res.status, RECIPE_STATUS_INSUFFICIENT_EVIDENCE)
        self.assertFalse(res.details.get("access_fault_confirmed", False))
        self.assertIn("Dereference was not attempted", res.not_applicable_reason)

        # Now when dereference_attempted=True, access fault should be confirmed
        context["dereference_attempted"] = True
        res_deref = self.registry.evaluate_recipe("RECIPE_INVALID_MEMORY_ACCESS", context)
        self.assertEqual(res_deref.status, RECIPE_STATUS_SUPPORTED)
        self.assertTrue(res_deref.details.get("access_fault_confirmed", False))

    # Case B: Mapped pointer != valid object
    def test_case_b_mapped_pointer_invalid_object(self):
        # Pointer is mapped, but object header / vtable is invalid/corrupted
        context = {
            "pointer_address": 0x7fff1000,
            "dereference_attempted": True,
            "object_valid": False,
            "maps": [{"start": 0x7fff0000, "end": 0x7fff5000, "perms": "rw-p"}],
        }
        res = self.registry.evaluate_recipe("RECIPE_INVALID_MEMORY_ACCESS", context)
        self.assertEqual(res.status, RECIPE_STATUS_SUPPORTED)
        self.assertTrue(res.details.get("corrupted_object_header", False))
        self.assertEqual(res.details.get("root_cause"), "CORRUPTED_OBJECT_HEADER")

    # Case C: Poison-like bytes without lifetime evidence != confirmed UAF
    def test_case_c_poison_bytes_without_lifetime_evidence(self):
        # Poison pattern observed (e.g. 0xdeadbeef), but allocator quarantine / epoch lifetime missing
        context = {
            "memory_pattern": "0xdeadbeef",
            "lifetime_evidence_available": False,
            "quarantine_record_found": False,
        }
        res = self.registry.evaluate_recipe("RECIPE_USE_AFTER_FREE", context)
        self.assertEqual(res.status, RECIPE_STATUS_INSUFFICIENT_EVIDENCE)
        self.assertFalse(res.details.get("uaf_confirmed", False))
        self.assertTrue(res.details.get("unconfirmed_poison_pattern", False))

        # With lifetime evidence / quarantine record
        context["lifetime_evidence_available"] = True
        context["quarantine_record_found"] = True
        res_uaf = self.registry.evaluate_recipe("RECIPE_USE_AFTER_FREE", context)
        self.assertEqual(res_uaf.status, RECIPE_STATUS_SUPPORTED)
        self.assertTrue(res_uaf.details.get("uaf_confirmed", False))

    # Case D: Single freelist observation != double free
    def test_case_d_single_freelist_observation(self):
        # Pointer observed in freelist once (normal freed chunk)
        context = {
            "freelist_occurrences": 1,
            "consecutive_free_events": 1,
        }
        res = self.registry.evaluate_recipe("RECIPE_DOUBLE_FREE", context)
        self.assertEqual(res.status, RECIPE_STATUS_INSUFFICIENT_EVIDENCE)
        self.assertTrue(res.details.get("single_freelist_observation", False))
        self.assertFalse(res.details.get("double_free_confirmed", False))

        # Pointer observed in freelist multiple times or consecutive free calls
        context["freelist_occurrences"] = 2
        res_df = self.registry.evaluate_recipe("RECIPE_DOUBLE_FREE", context)
        self.assertEqual(res_df.status, RECIPE_STATUS_SUPPORTED)
        self.assertTrue(res_df.details.get("double_free_confirmed", False))

    # Case E: RSS growth from initialization distinguished from sustained growth
    def test_case_e_transient_warmup_vs_sustained_growth(self):
        # Warmup sequence: rises then plateaus
        w_warmup = ObservationWindow(target_pid=1234)
        w_warmup.record_sample(MemorySample(epoch_id=1, timestamp=1.0, rss_kb=10000, pss_kb=8000, private_dirty_kb=5000, heap_vma_kb=20000))
        w_warmup.record_sample(MemorySample(epoch_id=2, timestamp=2.0, rss_kb=20000, pss_kb=16000, private_dirty_kb=10000, heap_vma_kb=30000))
        w_warmup.record_sample(MemorySample(epoch_id=3, timestamp=3.0, rss_kb=20050, pss_kb=16050, private_dirty_kb=10050, heap_vma_kb=30000))
        w_warmup.record_sample(MemorySample(epoch_id=4, timestamp=4.0, rss_kb=20050, pss_kb=16050, private_dirty_kb=10050, heap_vma_kb=30000))
        res_warmup = w_warmup.analyze_memory_behavior()
        self.assertEqual(res_warmup.behavior, MemoryBehavior.STABLE_PLATEAU)

        # Sustained growth sequence: continues growing every epoch
        w_sustained = ObservationWindow(target_pid=1234)
        w_sustained.record_sample(MemorySample(epoch_id=1, timestamp=1.0, rss_kb=10000, pss_kb=8000, private_dirty_kb=5000, heap_vma_kb=20000))
        w_sustained.record_sample(MemorySample(epoch_id=2, timestamp=2.0, rss_kb=15000, pss_kb=12000, private_dirty_kb=8000, heap_vma_kb=25000))
        w_sustained.record_sample(MemorySample(epoch_id=3, timestamp=3.0, rss_kb=20000, pss_kb=16000, private_dirty_kb=11000, heap_vma_kb=30000))
        w_sustained.record_sample(MemorySample(epoch_id=4, timestamp=4.0, rss_kb=25000, pss_kb=20000, private_dirty_kb=14000, heap_vma_kb=35000))
        res_sustained = w_sustained.analyze_memory_behavior()
        self.assertIn(res_sustained.behavior, [MemoryBehavior.SUSTAINED_GROWTH, MemoryBehavior.PROBABLE_LEAK, MemoryBehavior.CONFIRMED_LEAK])

    # Case F: Heap VMA growth distinguished from live object growth
    def test_case_f_heap_vma_growth_vs_live_object_growth(self):
        # VMA grows, but live objects and allocator allocated bytes remain flat
        context = {
            "vma_growth_detected": True,
            "heap_vma_delta": 64 * 1024 * 1024,
            "live_objects_growing": False,
            "allocator_allocated_delta": 0,
        }
        res = self.registry.evaluate_recipe("RECIPE_HEAP_GROWTH", context)
        self.assertEqual(res.status, RECIPE_STATUS_INSUFFICIENT_EVIDENCE)
        self.assertTrue(res.details.get("vma_reservation_only", False))
        self.assertFalse(res.details.get("live_leak_confirmed", False))

        # When live objects and allocated bytes grow together
        context["live_objects_growing"] = True
        context["allocator_allocated_delta"] = 32 * 1024 * 1024
        res_leak = self.registry.evaluate_recipe("RECIPE_HEAP_GROWTH", context)
        self.assertEqual(res_leak.status, RECIPE_STATUS_SUPPORTED)
        self.assertTrue(res_leak.details.get("live_leak_confirmed", False))

    # Case G: Large stable container != accumulating memory
    def test_case_g_large_stable_container(self):
        # Container has 1,000,000 elements, but delta is 0 across windows
        context = {
            "container_size": 1_000_000,
            "container_delta": 0,
            "monotonic_growth": False,
        }
        res = self.registry.evaluate_recipe("RECIPE_LONG_LIVED_OBJECT_ACCUMULATION", context)
        self.assertEqual(res.status, RECIPE_STATUS_NOT_APPLICABLE)
        self.assertTrue(res.details.get("stable_container", False))

        # Container growing monotonically
        context["container_delta"] = 50_000
        context["monotonic_growth"] = True
        # a count that grows is accumulation only with memory growing in the same window
        context["heap_growth_bytes"] = 8 * 1024 * 1024
        res_accum = self.registry.evaluate_recipe("RECIPE_LONG_LIVED_OBJECT_ACCUMULATION", context)
        self.assertEqual(res_accum.status, RECIPE_STATUS_SUPPORTED)

    # Case H: Incompatible alloc/free counters != compared
    def test_case_h_incompatible_counters_not_applicable(self):
        # Incompatible counter pairing: packet count vs byte count
        context = {
            "incompatible_counters": True,
            "counter1_unit": "packets",
            "counter2_unit": "bytes",
        }
        res = self.registry.evaluate_recipe("RECIPE_ALLOCATION_FREE_IMBALANCE", context)
        self.assertEqual(res.status, RECIPE_STATUS_NOT_APPLICABLE)
        self.assertIn("incompatible", res.not_applicable_reason.lower())

        # Compatible counters evaluated
        context_ok = {
            "incompatible_counters": False,
            "alloc_count": 5000,
            "free_count": 1000,
            "alloc_delta": 4000, "free_delta": 100,  # static ratio is not a leak: the gap grew over the window
            "counter1_unit": "chunks",
            "counter2_unit": "chunks",
        }
        res_ok = self.registry.evaluate_recipe("RECIPE_ALLOCATION_FREE_IMBALANCE", context_ok)
        self.assertEqual(res_ok.status, RECIPE_STATUS_SUPPORTED)

    # Case I: Unrelated capacity and length fields != paired
    def test_case_i_unrelated_fields_not_applicable(self):
        # Unrelated fields across different structures/subsystems
        context = {
            "unrelated_field_pair": True,
            "field1": "CustomerDatabase.cache_capacity",
            "field2": "AudioStream.sample_count",
        }
        res = self.registry.evaluate_recipe("RECIPE_INCONSISTENT_RELATED_VARIABLES", context)
        self.assertEqual(res.status, RECIPE_STATUS_NOT_APPLICABLE)
        self.assertIn("unrelated", res.not_applicable_reason.lower())

        # Structural discovery tool also rejects pairing
        discovery = CppStructuralDiscovery()
        pair_candidate = discovery.evaluate_candidate_pair(
            container_type="CustomerDatabase",
            field_name_a="cache_capacity",
            type_a="size_t",
            offset_a=0x10,
            field_name_b="sample_count",
            type_b="int",
            offset_b=0x200,
        )
        self.assertIsNone(pair_candidate)

    # Case J: State values without specification != classified illegal
    def test_case_j_state_without_spec_not_applicable(self):
        # Value observed, but no enum domain or transition rules specified
        context = {
            "current_state": 42,
            "missing_specification": True,
        }
        res = self.registry.evaluate_recipe("RECIPE_STATE_TRANSITION_VIOLATIONS", context)
        self.assertEqual(res.status, RECIPE_STATUS_NOT_APPLICABLE)
        self.assertIn("specification", res.not_applicable_reason.lower())

        # When explicit contract is provided
        context_contract = {
            "current_state": 42,
            "allowed_states": [0, 1, 2, 3],
            "missing_specification": False,
        }
        res_viol = self.registry.evaluate_recipe("RECIPE_STATE_TRANSITION_VIOLATIONS", context_contract)
        self.assertEqual(res_viol.status, RECIPE_STATUS_SUPPORTED)

    # Case K: Blocked threads without complete lock graph == INCONCLUSIVE
    def test_case_k_incomplete_lock_graph_inconclusive(self):
        # Contention observed, but lock ownership unresolved / incomplete graph
        context = {
            "incomplete_lock_graph": True,
            "blocked_threads_count": 2,
        }
        res = self.registry.evaluate_recipe("RECIPE_POTENTIAL_DEADLOCK_PATTERNS", context)
        self.assertEqual(res.status, RECIPE_STATUS_INSUFFICIENT_EVIDENCE)
        self.assertTrue(res.details.get("incomplete_graph", False))

        # WaitForGraph test for completeness
        wfg = WaitForGraph()
        wfg.add_thread(101, "Worker-1", "WAITING")
        wfg.add_lock("lock_1", 0xAAAA, "MUTEX")
        wfg.add_waiting_edge(101, "lock_1")
        wfg.add_unresolved_edge("lock_1", 101, "Kernel futex owner not in target task group")
        self.assertFalse(wfg.is_complete)
        self.assertEqual(len(wfg.find_cycles()), 0)

    # Case L: Circular wait observed once != persistent deadlock
    def test_case_l_circular_wait_transient_vs_persistent(self):
        # Single observation of circular wait (transient race / dynamic handoff)
        context = {
            "incomplete_lock_graph": False,
            "cycle_detected": True,
            "observation_count": 1,
            "is_persistent": False,
        }
        res_transient = self.registry.evaluate_recipe("RECIPE_POTENTIAL_DEADLOCK_PATTERNS", context)
        self.assertEqual(res_transient.status, RECIPE_STATUS_INSUFFICIENT_EVIDENCE)
        self.assertFalse(res_transient.details.get("is_persistent", False))
        self.assertEqual(res_transient.details.get("state"), ConcurrencyState.OBSERVED_CIRCULAR_WAIT.value)

        # Multi-sample persistence confirms persistent deadlock
        context["observation_count"] = 3
        context["is_persistent"] = True
        res_deadlock = self.registry.evaluate_recipe("RECIPE_POTENTIAL_DEADLOCK_PATTERNS", context)
        self.assertEqual(res_deadlock.status, RECIPE_STATUS_SUPPORTED)
        self.assertTrue(res_deadlock.details.get("is_persistent", False))
        self.assertEqual(res_deadlock.details.get("state"), ConcurrencyState.PERSISTENT_DEADLOCK.value)

    # Case M: Competing memory-growth hypotheses distinguished through additional observations
    def test_case_m_competing_hypotheses_discrimination(self):
        hyps = CompetingHypothesisManager.generate_competing_hypotheses(
            category="MEMORY_LEAK",
            context={"rss_delta_mb": 150, "pid": 1234},
        )
        self.assertGreaterEqual(len(hyps), 3)

        # Initial comparison: no discriminating observations yet
        res_init = CompetingHypothesisManager.compare(hyps)
        self.assertIsNotNone(res_init.recommended_discriminating_recipe)

        # Introduce confirming evidence for live heap growth and refuting cache warmup
        for h in hyps:
            if "Heap" in h.title:
                h.supporting_observations.append("RECIPE_HEAP_GROWTH: live chunks increased monotonically")
                h.confidence = 0.88
            elif "Cache" in h.title:
                h.contradicting_observations.append("RECIPE_HEAP_GROWTH: stable hit-ratio, not caching")
                h.confidence = 0.15
                h.status = VERDICT_REFUTED

        res_after = CompetingHypothesisManager.compare(hyps)
        self.assertIn("Heap", res_after.ranked_hypotheses[0]["title"])
        self.assertTrue(any(hyps[1].hypothesis_id in alt for alt in res_after.eliminated_alternatives))

    # Case N: Evidence IDs map to actual observations
    def test_case_n_evidence_id_maps_to_actual_observation(self):
        engine = ExpertDiagnosticEngine()
        session = engine.start_investigation(
            problem_statement="Investigate worker process memory leak",
            pid=os.getpid(),
        )
        # Run classification and planning
        session.step()  # CLASSIFIED
        session.step()  # ASSESSED
        session.step()  # PLANNED
        session.step()  # COLLECT_STEP

        # Verify evidence records contain real observed values
        valid_records = [r for r in session.collected_evidence_records if r.collection_status == "SUCCESS"]
        self.assertGreater(len(valid_records), 0)
        for rec in valid_records:
            self.assertIsNotNone(rec.evidence_id)
            self.assertIsNotNone(rec.observed_value)

        # And collected_evidence list contains valid entries
        self.assertGreater(len(session.collected_evidence), 0)
        for ev in session.collected_evidence:
            self.assertIn("evidence_id", ev)
            self.assertIn("observed_value", ev)

    # Case O: Next investigation action changes when contradictory evidence introduced
    def test_case_o_adaptive_action_selection_on_contradiction(self):
        engine = ExpertDiagnosticEngine()
        session = engine.start_investigation(
            problem_statement="Investigate severe heap memory leak and unbounded RSS growth",
            pid=os.getpid(),
        )
        session.step()  # CLASSIFY
        session.step()  # ASSESS
        session.step()  # PLAN

        # Mock evaluate_recipe to return RECIPE_STATUS_CONTRADICTED for the first collection step
        def mock_contradicted(recipe_or_id, context, prerequisites_met=True):
            rec_id = recipe_or_id.recipe_id if hasattr(recipe_or_id, "recipe_id") else str(recipe_or_id)
            return RecipeEvaluationResult(
                recipe_id=rec_id,
                status=RECIPE_STATUS_CONTRADICTED,
                confidence=0.1,
                confidence_basis="Contradicting observation",
                contradicting_facts=["Observation directly refutes hypothesis"],
                details={"contradicted": True},
            )

        with patch.object(session.recipe_registry, "evaluate_recipe", side_effect=mock_contradicted):
            res = session.step()  # COLLECT_STEP with contradiction
            self.assertEqual(res["action"], "COLLECT_STEP")

            # Verify that competing hypotheses were updated and a discriminating step was prioritized
            next_step = session.plan.steps[session.plan.current_step_index]
            self.assertEqual(next_step.priority, 1)
            self.assertIn("discrim", next_step.step_id)

    # Case P: Expert-specified variables and invariants influence plan
    def test_case_p_expert_overrides_influence_plan(self):
        engine = ExpertDiagnosticEngine()
        override = ExpertOverrideConstraint(
            variable_expression="SessionPool::active_count",
            related_variables=["SessionPool::active_count", "SessionPool::max_capacity"],
            invariant_expression="active_count <= max_capacity",
            problem_category="INCONSISTENT_STATE",
        )
        session = engine.start_investigation(
            problem_statement="Investigate session pool instability",
            pid=os.getpid(),
            expert_overrides=[override],
        )
        session.step()  # CLASSIFY
        session.step()  # ASSESS
        session.step()  # PLAN

        # Step 0 should be the prioritized expert override step
        first_step = session.plan.steps[0]
        self.assertEqual(first_step.priority, 1)
        self.assertIn("[Expert Override]", first_step.recipe_name)
        self.assertEqual(first_step.recipe_id, "RECIPE_INCONSISTENT_RELATED_VARIABLES")
        self.assertIn("SessionPool", first_step.rationale)


if __name__ == "__main__":
    unittest.main()
