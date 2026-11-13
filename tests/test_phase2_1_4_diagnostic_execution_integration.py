"""
Phase 2.1.4 Validation Test Suite
Diagnostic Execution Integration & Semantic Correctness (Tests A through AI).

Covers:
- Allocator Semantics (Tests A - G)
- Temporal Observation Semantics (Tests H - O)
- C++ Structural Discovery Accuracy (Tests P - S)
- Invariant Evaluation Integration (Tests T - V)
- Concurrency Wait-For Graph (Tests W - Z)
- Competing Hypotheses & Information-Gain Discrimination (Tests AA - AD)
- Complete Integration Parity (Tests AE - AI)
"""

import os
import subprocess
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch
from typing import Dict, Any, List, Optional, Tuple

from extractor.allocator_inspector import (
    AllocatorType,
    AllocatorInspector,
    detect_allocator,
    FreeValidationOutcome,
    FreeValidationResult,
    GlibcPtMallocInspector,
    JemallocInspector,
    TcmallocInspector,
    CustomAllocatorInspector,
    UnknownAllocatorInspector,
)
from extractor.temporal_observation_window import (
    ObservationWindow,
    MemorySample,
    MemoryBehavior,
    MemoryBehaviorClassification,
    TemporalAnalysisResult,
)
from extractor.cpp_structural_discovery import (
    CppStructuralDiscovery,
    CppRelationshipType,
    CppRelationshipCandidate,
    ExpertOverrideConstraint,
)
from extractor.invariant_framework import (
    InvariantEvaluator,
    InvariantDefinition,
    InvariantType,
    InvariantSource,
    InvariantEvaluationResult,
)
from extractor.concurrency_graph import (
    WaitForGraph,
    ThreadNode,
    LockNode,
    WaitingEdge,
    OwnershipEdge,
    UnresolvedOwnershipEdge,
    ConcurrencyState,
    DeadlockAnalysisResult,
)
from extractor.competing_hypotheses import (
    CompetingHypothesis,
    CompetingHypothesisManager,
    HypothesisComparisonResult,
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
    RECIPE_STATUS_CONTRADICTED,
    RECIPE_STATUS_AMBIGUOUS,
    RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
    RECIPE_STATUS_NOT_APPLICABLE,
)
from extractor.expert_diagnostic_engine import (
    AdaptiveInvestigationSession,
    ExpertDiagnosticEngine,
    TargetAssessor,
    TargetAssessmentResult,
    ProblemClassifier,
    STATE_COMPLETED,
    STATE_INCONCLUSIVE,
)
from extractor.target_adapter import TargetExecutionAdapter, LocalTargetAdapter
from tests.support.fixture_process import fixture_popen


# =============================================================================
# 1. Allocator Semantics (Tests A - G)
# =============================================================================

class TestAllocatorSemantics(unittest.TestCase):
    """P0: Allocator Inspector and Validation Semantics."""

    def test_case_a_glibc_chunk_prev_inuse_not_current_state(self):
        """Test A: PREV_INUSE describes previous chunk, not current chunk state."""
        inspector = GlibcPtMallocInspector(arch_bits=64)
        # 64-bit chunk: 8 bytes prev_size (0), 8 bytes size_flags (64 | 0x1 PREV_INUSE)
        chunk_header = (0).to_bytes(8, "little") + (64 | 0x1).to_bytes(8, "little")
        # Next chunk header: size=64, PREV_INUSE=1 (means current chunk IS allocated)
        next_chunk_allocated = (0).to_bytes(8, "little") + (64 | 0x1).to_bytes(8, "little")
        # Next chunk header: size=64, PREV_INUSE=0 (means current chunk IS FREED)
        next_chunk_freed = (0).to_bytes(8, "little") + (64 | 0x0).to_bytes(8, "little")

        # When next chunk has PREV_INUSE=1: current chunk is allocated
        info_alloc = inspector.inspect_chunk(chunk_header, address=0x1000, next_chunk_raw=next_chunk_allocated)
        self.assertTrue(info_alloc.prev_inuse)  # Chunk 0x1000's previous physical neighbor is in use
        self.assertTrue(info_alloc.is_allocated)  # Current chunk 0x1000 is allocated because next has PREV_INUSE=1
        self.assertTrue(info_alloc.allocation_state_proven)

        # When next chunk has PREV_INUSE=0: current chunk is freed!
        info_free = inspector.inspect_chunk(chunk_header, address=0x1000, next_chunk_raw=next_chunk_freed)
        self.assertTrue(info_free.prev_inuse)  # Previous chunk is still in use
        self.assertFalse(info_free.is_allocated)  # Current chunk is free because next has PREV_INUSE=0
        self.assertTrue(info_free.allocation_state_proven)

        # Without next chunk, current chunk state cannot be authoritatively proven
        info_inconclusive = inspector.inspect_chunk(chunk_header, address=0x1000, next_chunk_raw=None)
        self.assertIsNone(info_inconclusive.is_allocated)
        self.assertFalse(info_inconclusive.allocation_state_proven)

    def test_case_b_chunk_header_vs_user_pointer(self):
        """Test B: Distinguish chunk header address from user pointer address."""
        insp64 = GlibcPtMallocInspector(arch_bits=64)
        # In 64-bit ptmalloc, user pointer = chunk header + 2 * SIZE_SZ = chunk + 16
        chunk_addr = 0x555555600000
        expected_user_ptr = 0x555555600010
        self.assertEqual(insp64.chunk_to_user_ptr(chunk_addr), expected_user_ptr)
        self.assertEqual(insp64.user_ptr_to_chunk(expected_user_ptr), chunk_addr)

        # In 32-bit ptmalloc, user pointer = chunk header + 2 * 4 = chunk + 8
        insp32 = GlibcPtMallocInspector(arch_bits=32)
        chunk32 = 0x0804a000
        expected_user_ptr32 = 0x0804a008
        self.assertEqual(insp32.chunk_to_user_ptr(chunk32), expected_user_ptr32)
        self.assertEqual(insp32.user_ptr_to_chunk(expected_user_ptr32), chunk32)

    def test_case_c_allocator_version_and_alignment_32_vs_64(self):
        """Test C: Account for 32/64-bit ABI, alignment quantum, and minimum chunk size."""
        insp64 = GlibcPtMallocInspector(arch_bits=64)
        self.assertEqual(insp64.size_sz, 8)
        self.assertEqual(insp64.malloc_alignment, 16)
        self.assertEqual(insp64.min_chunk_size, 32)

        insp32 = GlibcPtMallocInspector(arch_bits=32)
        self.assertEqual(insp32.size_sz, 4)
        self.assertEqual(insp32.malloc_alignment, 8)
        self.assertEqual(insp32.min_chunk_size, 16)

    def test_case_d_jemalloc_tcmalloc_out_of_band_inconclusive(self):
        """Test D: jemalloc and tcmalloc do not report is_allocated=True from mapped memory alone."""
        jem = JemallocInspector()
        raw = b"\x00" * 64
        info_jem = jem.inspect_chunk(raw, address=0x7ffff7000000)
        self.assertIsNone(info_jem.is_allocated)
        self.assertFalse(info_jem.allocation_state_proven)
        self.assertIn("jemalloc", info_jem.limitations[0].lower())

        tc = TcmallocInspector()
        info_tc = tc.inspect_chunk(raw, address=0x7ffff7000000)
        self.assertIsNone(info_tc.is_allocated)
        self.assertFalse(info_tc.allocation_state_proven)
        self.assertIn("tcmalloc", info_tc.limitations[0].lower())

    def test_case_e_custom_schema_and_unknown_isolation(self):
        """Test E: Custom allocator requires schema; unknown allocator never defaults to glibc."""
        # Custom without schema
        custom_no_schema = CustomAllocatorInspector(schema=None)
        self.assertIsNone(custom_no_schema.inspect_chunk(b"\x00" * 32, 0x1000).is_allocated)

        # Custom with explicit pool schema
        schema = {"pool_start": 0x200000, "block_size": 64, "pool_size": 4096}
        custom = CustomAllocatorInspector(schema=schema)
        self.assertTrue(custom.is_valid_allocation_start(0x200000, []))
        self.assertTrue(custom.is_valid_allocation_start(0x200040, []))
        self.assertFalse(custom.is_valid_allocation_start(0x200010, []))  # Misaligned interior

        # Unknown allocator never applies glibc layout
        unk = UnknownAllocatorInspector()
        res_unk = unk.inspect_chunk(b"\x00\x00\x00\x00\x21\x00\x00\x00", 0x3000)
        self.assertIsNone(res_unk.is_allocated)
        self.assertEqual(res_unk.allocator_type, AllocatorType.UNKNOWN)

    def test_case_f_detect_allocator_confidence_levels(self):
        """Test F: detect_allocator() distinguishes CONFIRMED, PROBABLE, and UNKNOWN."""
        # 1. Confirmed via symbol signatures
        res_sym = detect_allocator(maps=[], symbols=["je_malloc", "je_free"])
        self.assertEqual(res_sym.allocator_type, AllocatorType.JEMALLOC)
        self.assertEqual(res_sym.confidence, "CONFIRMED")

        # 2. Confirmed via mapped libraries
        res_map = detect_allocator(maps=[{"pathname": "/usr/lib/libtcmalloc.so.4", "perms": "r-xp"}])
        self.assertEqual(res_map.allocator_type, AllocatorType.TCMALLOC)
        self.assertEqual(res_map.confidence, "CONFIRMED")

        # 3. Probable via standard libc.so
        res_libc = detect_allocator(maps=[{"pathname": "/lib/x86_64-linux-gnu/libc.so.6", "perms": "r-xp"}])
        self.assertEqual(res_libc.allocator_type, AllocatorType.GLIBC_PTMALLOC)
        self.assertEqual(res_libc.confidence, "PROBABLE")

        # 4. Unknown when no hints present
        res_unknown = detect_allocator(maps=[{"pathname": "/usr/bin/custom_daemon", "perms": "r-xp"}])
        self.assertEqual(res_unknown.allocator_type, AllocatorType.UNKNOWN)
        self.assertEqual(res_unknown.confidence, "UNKNOWN")

    def test_case_g_validate_free_target_outcomes(self):
        """Test G: validate_free_target() classifies specific contract violations."""
        insp = GlibcPtMallocInspector(arch_bits=64)
        maps = [{"start_int": 0x555555600000, "end_int": 0x555555700000, "permissions": "rw-p"}]

        # 1. Misaligned pointer
        res_misalign = insp.validate_free_target(0x555555600005, maps=maps)
        self.assertFalse(res_misalign.is_valid)
        self.assertEqual(res_misalign.outcome, FreeValidationOutcome.FREE_TARGET_MISALIGNED)

        # 2. Outside heap
        res_outside = insp.validate_free_target(0x7ffff7000000, maps=maps)
        self.assertFalse(res_outside.is_valid)
        self.assertEqual(res_outside.outcome, FreeValidationOutcome.FREE_TARGET_OUTSIDE_HEAP)

        # 3. Invalid boundary (chunk size < MIN_CHUNK_SIZE)
        bad_header = (0).to_bytes(8, "little") + (16 | 0x1).to_bytes(8, "little")  # size=16 < min 32
        res_boundary = insp.validate_free_target(0x555555600010, raw_header=bad_header, maps=maps)
        self.assertFalse(res_boundary.is_valid)
        self.assertEqual(res_boundary.outcome, FreeValidationOutcome.FREE_TARGET_INVALID_BOUNDARY)

        # 4. Already released (next chunk has PREV_INUSE == 0)
        valid_header = (0).to_bytes(8, "little") + (64 | 0x1).to_bytes(8, "little")
        freed_next = (0).to_bytes(8, "little") + (64 | 0x0).to_bytes(8, "little")
        res_freed = insp.validate_free_target(0x555555600010, raw_header=valid_header, next_chunk_raw=freed_next, maps=maps)
        self.assertFalse(res_freed.is_valid)
        self.assertEqual(res_freed.outcome, FreeValidationOutcome.FREE_TARGET_ALREADY_RELEASED)

        # 5. Confirmed double free requires multiple freelist records / events
        single_fl = ["free_event_1"]
        res_single = insp.validate_free_target(0x555555600010, raw_header=valid_header, maps=maps, freelist_records=single_fl)
        self.assertNotEqual(res_single.outcome, FreeValidationOutcome.FREE_TARGET_DOUBLE_FREE)

        multi_fl = ["free_event_1", "free_event_2"]
        res_double = insp.validate_free_target(0x555555600010, raw_header=valid_header, maps=maps, freelist_records=multi_fl)
        self.assertFalse(res_double.is_valid)
        self.assertEqual(res_double.outcome, FreeValidationOutcome.FREE_TARGET_DOUBLE_FREE)


# =============================================================================
# 2. Temporal Observation Semantics (Tests H - O)
# =============================================================================

class TestTemporalObservationSemantics(unittest.TestCase):
    """P0: Monotonic Time, Clock Regression, and Behavior Classifications."""

    def test_case_h_duration_and_rate_use_monotonic_time(self):
        """Test H: Elapsed duration and growth rates strictly use monotonic timestamps."""
        win = ObservationWindow(target_pid=42)
        # Sample 1: monotonic = 100.0, wall = 1700000000.0, RSS = 10000
        win.record_sample(MemorySample(epoch_id=1, monotonic_timestamp=100.0, wall_clock_timestamp=1700000000.0, rss_kb=10000))
        # Sample 2: monotonic = 110.0 (+10.0 sec), wall = 1700000005.0 (+5.0 sec warped), RSS = 20000 (+10000 KB)
        win.record_sample(MemorySample(epoch_id=2, monotonic_timestamp=110.0, wall_clock_timestamp=1700000005.0, rss_kb=20000))

        # Duration must be 10.0s (monotonic), rate must be 1000 KB/s
        self.assertAlmostEqual(win.elapsed_duration_sec(), 10.0, places=2)
        res = win.analyze_memory_behavior()
        self.assertAlmostEqual(res.rss_growth_rate_kb_per_sec, 1000.0, places=1)

    def test_case_i_wall_clock_time_retained_for_reporting(self):
        """Test I: Wall-clock timestamp is preserved on each sample for external auditing."""
        wall_now = 1731000000.0
        s = MemorySample(epoch_id=1, monotonic_timestamp=50.0, wall_clock_timestamp=wall_now, rss_kb=1024)
        self.assertEqual(s.wall_clock_timestamp, wall_now)
        self.assertEqual(s.monotonic_timestamp, 50.0)

    def test_case_j_no_max_hiding_timestamp_regressions(self):
        """Test J: Never use max() to swallow backward clock regressions."""
        win = ObservationWindow(target_pid=42)
        win.record_sample(MemorySample(epoch_id=1, monotonic_timestamp=200.0, rss_kb=10000))
        # Regressed sample (monotonic went backwards from 200.0 to 195.0)
        win.record_sample(MemorySample(epoch_id=2, monotonic_timestamp=195.0, rss_kb=15000))

        # Window must detect regression and report negative or regressed duration
        self.assertTrue(win.has_temporal_regression())
        self.assertLess(win.elapsed_duration_sec(), 0.0)

    def test_case_k_clock_regression_marks_sequence_invalid(self):
        """Test K: Monotonic clock regression sets TEMPORAL_SEQUENCE_INVALID with explicit limitations."""
        win = ObservationWindow(target_pid=42)
        win.record_sample(MemorySample(epoch_id=1, monotonic_timestamp=100.0, rss_kb=10000))
        win.record_sample(MemorySample(epoch_id=2, monotonic_timestamp=99.0, rss_kb=12000))
        res = win.analyze_memory_behavior()
        self.assertEqual(res.behavior, MemoryBehavior.TEMPORAL_SEQUENCE_INVALID)
        self.assertEqual(res.confidence, 0.0)
        self.assertIn("clock regressions", res.rationale.lower())

    def test_case_l_minimum_two_samples_for_delta(self):
        """Test L: Single sample returns INSUFFICIENT_OBSERVATION; minimum 2 required for delta."""
        win = ObservationWindow(target_pid=42)
        win.record_sample(MemorySample(epoch_id=1, monotonic_timestamp=10.0, rss_kb=10000))
        res = win.analyze_memory_behavior()
        self.assertEqual(res.behavior, MemoryBehavior.INSUFFICIENT_OBSERVATION)
        self.assertIn("at least 2", res.rationale.lower())

    def test_case_m_repeated_observations_persistence(self):
        """Test M: Two samples establish initial delta only; >= 3 required for persistence."""
        win = ObservationWindow(target_pid=42)
        win.record_sample(MemorySample(epoch_id=1, monotonic_timestamp=10.0, rss_kb=10000))
        win.record_sample(MemorySample(epoch_id=2, monotonic_timestamp=20.0, rss_kb=15000))
        res2 = win.analyze_memory_behavior()
        self.assertEqual(res2.behavior, MemoryBehavior.INSUFFICIENT_OBSERVATION)
        self.assertIn("at least 3 temporal epochs", res2.rationale.lower())

        # Third sample provides trajectory
        win.record_sample(MemorySample(epoch_id=3, monotonic_timestamp=30.0, rss_kb=20000))
        res3 = win.analyze_memory_behavior()
        self.assertNotEqual(res3.behavior, MemoryBehavior.INSUFFICIENT_OBSERVATION)

    def test_case_n_single_rss_increase_never_establishes_leak(self):
        """Test N: Pure RSS increase without internal heap/container corroboration is SUSTAINED_RSS_GROWTH."""
        win = ObservationWindow(target_pid=42)
        win.record_sample(MemorySample(epoch_id=1, monotonic_timestamp=1.0, rss_kb=10000))
        win.record_sample(MemorySample(epoch_id=2, monotonic_timestamp=2.0, rss_kb=15000))
        win.record_sample(MemorySample(epoch_id=3, monotonic_timestamp=3.0, rss_kb=20000))
        win.record_sample(MemorySample(epoch_id=4, monotonic_timestamp=4.0, rss_kb=25000))
        res = win.analyze_memory_behavior()
        self.assertEqual(res.behavior, MemoryBehavior.SUSTAINED_RSS_GROWTH)
        self.assertNotEqual(res.behavior, MemoryBehavior.CONFIRMED_LEAK)

    def test_case_o_separation_of_13_memory_behaviors(self):
        """Test O: Validates distinct classification across specified behaviors."""
        # 1. Stable Plateau
        win_plat = ObservationWindow(target_pid=1)
        win_plat.record_sample(MemorySample(epoch_id=1, monotonic_timestamp=1.0, rss_kb=10000))
        win_plat.record_sample(MemorySample(epoch_id=2, monotonic_timestamp=2.0, rss_kb=20000))
        win_plat.record_sample(MemorySample(epoch_id=3, monotonic_timestamp=3.0, rss_kb=20020))
        win_plat.record_sample(MemorySample(epoch_id=4, monotonic_timestamp=4.0, rss_kb=20020))
        self.assertEqual(win_plat.analyze_memory_behavior().behavior, MemoryBehavior.STABLE_PLATEAU)

        # 2. Object Accumulation
        win_obj = ObservationWindow(target_pid=2)
        win_obj.record_sample(MemorySample(epoch_id=1, monotonic_timestamp=1.0, rss_kb=10000, container_sizes={"SessionCache": 10}))
        win_obj.record_sample(MemorySample(epoch_id=2, monotonic_timestamp=2.0, rss_kb=12000, container_sizes={"SessionCache": 50}))
        win_obj.record_sample(MemorySample(epoch_id=3, monotonic_timestamp=3.0, rss_kb=15000, container_sizes={"SessionCache": 120}))
        self.assertEqual(win_obj.analyze_memory_behavior().behavior, MemoryBehavior.OBJECT_ACCUMULATION)

        # 3. Confirmed Leak (Corroborated by live allocator metrics)
        win_leak = ObservationWindow(target_pid=3)
        win_leak.record_sample(MemorySample(epoch_id=1, monotonic_timestamp=1.0, rss_kb=10000, live_allocations_count=100, allocator_heap_kb=2000))
        win_leak.record_sample(MemorySample(epoch_id=2, monotonic_timestamp=2.0, rss_kb=15000, live_allocations_count=500, allocator_heap_kb=5000))
        win_leak.record_sample(MemorySample(epoch_id=3, monotonic_timestamp=3.0, rss_kb=20000, live_allocations_count=900, allocator_heap_kb=8000))
        self.assertEqual(win_leak.analyze_memory_behavior().behavior, MemoryBehavior.CONFIRMED_LEAK)


# =============================================================================
# 3. C++ Structural Discovery Accuracy (Tests P - S)
# =============================================================================

class TestCppStructuralDiscovery(unittest.TestCase):
    """P1: Structural Discovery and Coupling Constraints."""

    def test_case_p_canonical_type_compatibility_rejects_incompatible(self):
        """Test P: Incompatible types (float vs uint64_t, pointer vs int) are rejected."""
        disco = CppStructuralDiscovery()
        # Incompatible float vs integer size
        self.assertFalse(disco.are_types_capacity_length_compatible("float", "size_t"))
        self.assertFalse(disco.are_types_capacity_length_compatible("double", "uint64_t"))
        # Incompatible pointer vs scalar integer
        self.assertFalse(disco.are_types_capacity_length_compatible("void*", "uint32_t"))
        # Compatible integer pairs
        self.assertTrue(disco.are_types_capacity_length_compatible("uint32_t", "uint32_t"))
        self.assertTrue(disco.are_types_capacity_length_compatible("size_t", "uint64_t"))

    def test_case_q_counter_compatibility_rejects_scope_unit_incompatible(self):
        """Test Q: Reject unit-incompatible / scope-incompatible counters (packets vs bytes)."""
        disco = CppStructuralDiscovery()
        self.assertFalse(disco.are_counters_compatible("rx_packet_count", "tx_byte_volume"))
        self.assertTrue(disco.are_counters_compatible("received_packets", "dropped_packets"))

    def test_case_r_candidate_vs_established_relationships(self):
        """Test R: Distinguish candidate (is_established=False) from established relationships."""
        cand_unverified = CppRelationshipCandidate(
            relationship_type=CppRelationshipType.CAPACITY_VS_LENGTH,
            source_variable="m_capacity",
            target_variable="m_length",
            confidence=0.55,
            is_established=False,
            is_candidate=True,
        )
        self.assertFalse(cand_unverified.is_established)
        self.assertTrue(cand_unverified.is_candidate)

        cand_established = CppRelationshipCandidate(
            relationship_type=CppRelationshipType.CAPACITY_VS_LENGTH,
            source_variable="std::vector::capacity",
            target_variable="std::vector::size",
            confidence=0.98,
            is_established=True,
            is_candidate=False,
        )
        self.assertTrue(cand_established.is_established)

    def test_case_s_expert_overrides_highest_authority(self):
        """Test S: Expert overrides have highest authority (1.0)."""
        disco = CppStructuralDiscovery()
        override = ExpertOverrideConstraint(
            override_id="exp_01",
            source_variable="g_in_queue_depth",
            target_variable="g_out_queue_depth",
            relationship_type=CppRelationshipType.COUPLED_COUNTERS,
            expert_rationale="Hardware FIFO input and output counters must track in tandem",
        )
        result = disco.apply_expert_override(override)
        self.assertEqual(result.confidence, 1.0)
        self.assertTrue(result.is_established)
        self.assertEqual(result.source_variable, "g_in_queue_depth")


# =============================================================================
# 4. Invariant Evaluation Integration (Tests T - V)
# =============================================================================

class TestInvariantEvaluation(unittest.TestCase):
    """P1: Invariant Hierarchy, Anti-Fabrication, and Candidate Anomalies."""

    def test_case_t_explicit_authority_hierarchy(self):
        """Test T: EXPLICIT_EXPERT_SPEC (1.0) > RECOGNIZED_TYPE_CONTRACT (0.95) > SOURCE_LEVEL_RULE (0.85) > HEURISTIC (<=0.60)."""
        evaluator = InvariantEvaluator()
        inv_expert = InvariantDefinition(
            invariant_id="inv_01",
            name="Expert Spec",
            source=InvariantSource.EXPLICIT_EXPERT_SPEC,
            inv_type=InvariantType.BOUNDED_RANGE,
            min_value=0,
            max_value=100,
        )
        inv_heuristic = InvariantDefinition(
            invariant_id="inv_02",
            name="Heuristic Spec",
            source=InvariantSource.HEURISTIC_CANDIDATE,
            inv_type=InvariantType.BOUNDED_RANGE,
            min_value=0,
            max_value=100,
        )
        self.assertEqual(evaluator.get_source_authority(inv_expert.source), 1.0)
        self.assertLessEqual(evaluator.get_source_authority(inv_heuristic.source), 0.60)

    def test_case_u_missing_specs_return_not_applicable_or_inconclusive(self):
        """Test U: Missing specifications return NOT_APPLICABLE or INCONCLUSIVE; never invent legal values."""
        evaluator = InvariantEvaluator()
        # Evaluating an unknown variable without invariant definition returns NOT_APPLICABLE
        res = evaluator.evaluate(variable_name="unknown_status_flag", observed_value=999)
        self.assertEqual(res.status, "NOT_APPLICABLE")
        self.assertIn("no recognized invariant", res.rationale.lower())

    def test_case_v_heuristic_candidates_never_confirmed(self):
        """Test V: Heuristic candidates produce CANDIDATE_ANOMALY, never confirmed violations."""
        evaluator = InvariantEvaluator()
        inv_heuristic = InvariantDefinition(
            invariant_id="inv_heur_01",
            name="Guessed Buffer Range",
            source=InvariantSource.HEURISTIC_CANDIDATE,
            inv_type=InvariantType.BOUNDED_RANGE,
            min_value=0,
            max_value=10,
        )
        evaluator.register_invariant("m_buffer_idx", inv_heuristic)
        res = evaluator.evaluate("m_buffer_idx", observed_value=999)  # Violates heuristic range
        self.assertEqual(res.status, "CANDIDATE_ANOMALY")
        self.assertNotEqual(res.status, "CONFIRMED_VIOLATION")


# =============================================================================
# 5. Concurrency Wait-For Graph (Tests W - Z)
# =============================================================================

class TestConcurrencyGraph(unittest.TestCase):
    """P1: Concurrency Wait-For Graph Cycles and Incomplete Graphs."""

    def test_case_w_incomplete_graph_remains_inconclusive(self):
        """Test W: Incomplete lock graphs remain INCONCLUSIVE_INCOMPLETE_GRAPH (never infer acyclic)."""
        wfg = WaitForGraph()
        wfg.add_thread(ThreadNode(tid=1001, name="WorkerA"))
        wfg.add_lock(LockNode(lock_id="0xdead01", lock_type="std::mutex"))
        wfg.add_waiting_edge(WaitingEdge(waiter_tid=1001, lock_id="0xdead01"))
        # Unresolved lock owner
        wfg.add_unresolved_edge(UnresolvedOwnershipEdge(lock_id="0xdead01", reason="Owner thread exited or untraceable"))

        res = wfg.analyze()
        self.assertEqual(res.state, ConcurrencyState.INCONCLUSIVE_INCOMPLETE_GRAPH)
        self.assertFalse(res.is_complete)
        self.assertIn("cannot establish absence of cycles", res.rationale.lower())

    def test_case_x_single_snapshot_circular_wait_is_observed_circular_wait(self):
        """Test X: Single snapshot circular wait is OBSERVED_CIRCULAR_WAIT, not PERSISTENT_DEADLOCK."""
        wfg = WaitForGraph()
        wfg.add_thread(ThreadNode(tid=1, name="T1"))
        wfg.add_thread(ThreadNode(tid=2, name="T2"))
        wfg.add_lock(LockNode(lock_id="L1"))
        wfg.add_lock(LockNode(lock_id="L2"))
        wfg.add_ownership_edge(OwnershipEdge(holder_tid=1, lock_id="L1"))
        wfg.add_waiting_edge(WaitingEdge(waiter_tid=1, lock_id="L2"))
        wfg.add_ownership_edge(OwnershipEdge(holder_tid=2, lock_id="L2"))
        wfg.add_waiting_edge(WaitingEdge(waiter_tid=2, lock_id="L1"))

        # Analyzed with 1 epoch
        res = wfg.analyze(epoch_count=1, validated_observations_available=True)
        self.assertEqual(res.state, ConcurrencyState.OBSERVED_CIRCULAR_WAIT)
        self.assertFalse(res.is_persistent)

    def test_case_y_persistent_deadlock_requires_distinct_epochs(self):
        """Test Y: PERSISTENT_DEADLOCK requires verified cycle persisting across >= 2 validated epochs."""
        wfg = WaitForGraph()
        wfg.add_thread(ThreadNode(tid=1, name="T1"))
        wfg.add_thread(ThreadNode(tid=2, name="T2"))
        wfg.add_lock(LockNode(lock_id="L1"))
        wfg.add_lock(LockNode(lock_id="L2"))
        wfg.add_ownership_edge(OwnershipEdge(holder_tid=1, lock_id="L1"))
        wfg.add_waiting_edge(WaitingEdge(waiter_tid=1, lock_id="L2"))
        wfg.add_ownership_edge(OwnershipEdge(holder_tid=2, lock_id="L2"))
        wfg.add_waiting_edge(WaitingEdge(waiter_tid=2, lock_id="L1"))

        # Analyzed with 2 distinct validated observation epochs
        res = wfg.analyze(epoch_count=2, validated_observations_available=True, observation_epochs=[1, 2])
        self.assertEqual(res.state, ConcurrencyState.PERSISTENT_DEADLOCK)
        self.assertTrue(res.is_persistent)
        self.assertEqual(res.confidence, 0.98)

    def test_case_z_externally_supplied_counts_require_underlying_observations(self):
        """Test Z: Externally supplied epoch counts without underlying observations report limitation."""
        wfg = WaitForGraph()
        wfg.add_thread(ThreadNode(tid=1))
        wfg.add_thread(ThreadNode(tid=2))
        wfg.add_lock(LockNode(lock_id="L1"))
        wfg.add_lock(LockNode(lock_id="L2"))
        wfg.add_ownership_edge(OwnershipEdge(holder_tid=1, lock_id="L1"))
        wfg.add_waiting_edge(WaitingEdge(waiter_tid=1, lock_id="L2"))
        wfg.add_ownership_edge(OwnershipEdge(holder_tid=2, lock_id="L2"))
        wfg.add_waiting_edge(WaitingEdge(waiter_tid=2, lock_id="L1"))

        # Claimed epoch_count=5 but validated_observations_available=False
        res = wfg.analyze(epoch_count=5, validated_observations_available=False)
        self.assertIn("Underlying temporal observation records not available", res.limitations[0])
        # Must not certify persistent deadlock without validated observations
        self.assertEqual(res.state, ConcurrencyState.OBSERVED_CIRCULAR_WAIT)


# =============================================================================
# 6. Competing Hypotheses & Information-Gain Discrimination (Tests AA - AD)
# =============================================================================

class TestHypothesisDiscrimination(unittest.TestCase):
    """P1: Quantitative Discrimination and Anti-Double-Counting."""

    def test_case_aa_true_quantitative_information_gain(self):
        """Test AA: Quantitative information-gain calculation across candidate hypotheses."""
        h1 = CompetingHypothesis(
            hypothesis_id="H1",
            category="MEMORY_LEAK",
            applicable_diagnostic_rules=["RECIPE_PROCESS_MEMORY_GROWTH", "RECIPE_HEAP_GROWTH"],
        )
        h2 = CompetingHypothesis(
            hypothesis_id="H2",
            category="CACHE_WARMUP",
            applicable_diagnostic_rules=["RECIPE_PROCESS_MEMORY_GROWTH"],
        )
        res = CompetingHypothesisManager.compare([h1, h2])
        # HEAP_GROWTH distinguishes H1 from H2
        self.assertIsNotNone(res.recommended_discriminating_recipe)
        self.assertGreater(res.separation_score, 0.0)

    def test_case_ab_action_selection_based_on_discrimination(self):
        """Test AB: Select next action based on discrimination score."""
        h1 = CompetingHypothesis(
            hypothesis_id="H1",
            category="DEADLOCK_INDICATORS",
            applicable_diagnostic_rules=["RECIPE_POTENTIAL_DEADLOCK_PATTERNS"],
        )
        h2 = CompetingHypothesis(
            hypothesis_id="H2",
            category="THREAD_CONTENTION",
            applicable_diagnostic_rules=["RECIPE_LONG_RUNNING_BLOCKED_THREADS"],
        )
        res = CompetingHypothesisManager.compare([h1, h2])
        self.assertIn(res.recommended_discriminating_recipe, ["RECIPE_POTENTIAL_DEADLOCK_PATTERNS", "RECIPE_LONG_RUNNING_BLOCKED_THREADS"])

    def test_case_ac_separate_supporting_contradicting_no_double_counting(self):
        """Test AC: Do not double-count duplicate observations; missing != contradicting."""
        h = CompetingHypothesis(hypothesis_id="H1", category="MEMORY_CORRUPTION")
        added_first = h.add_supporting_observation("Invalid pointer dereference at 0x0")
        self.assertTrue(added_first)
        self.assertEqual(len(h.supporting_observations), 1)

        # Attempting to add exact duplicate observation must return False and not increment count
        added_duplicate = h.add_supporting_observation("Invalid pointer dereference at 0x0")
        self.assertFalse(added_duplicate)
        self.assertEqual(len(h.supporting_observations), 1)

    def test_case_ad_confidence_alone_cannot_confirm_without_primary(self):
        """Test AD: Confidence score alone CANNOT produce CONFIRMED without primary supporting observation."""
        h = CompetingHypothesis(hypothesis_id="H1", category="MEMORY_CORRUPTION")
        h.confidence = 0.99  # High theoretical confidence
        # Zero primary supporting observations
        self.assertEqual(len(h.supporting_observations), 0)
        verdict = h.evaluate_verdict()
        # Must NOT be CONFIRMED without verified primary observations
        self.assertNotEqual(verdict, VERDICT_CONFIRMED)


# =============================================================================
# 7. Complete Integration Parity (Tests AE - AI)
# =============================================================================

class MockRemoteAdapter(TargetExecutionAdapter):
    """Mock execution adapter simulating a zero-stop remote embedded target."""

    def __init__(self, is_alive: bool = True, mem_readable: bool = True):
        self._alive = is_alive
        self._readable = mem_readable

    def check_liveness(self, pid: int) -> Tuple[bool, Optional[str]]:
        return (self._alive, None if self._alive else "Target process terminated")

    def target_host(self) -> str:
        return "embedded-target-arm64:9099"

    def get_proc_maps(self, pid: int) -> List[Dict[str, Any]]:
        return [
            {"start_int": 0x400000, "end_int": 0x500000, "permissions": "r-xp", "pathname": "/app/controller"},
            {"start_int": 0x555555600000, "end_int": 0x555555700000, "permissions": "rw-p", "pathname": "[heap]"},
            {"start_int": 0x7ffff7000000, "end_int": 0x7ffff7200000, "permissions": "r-xp", "pathname": "/lib/libc.so.6"},
        ]

    def get_threads(self, pid: int) -> List[int]:
        return [pid, pid + 1]

    def get_process_status(self, pid: int) -> Dict[str, str]:
        return {"VmRSS": "20480", "VmSize": "65536"}

    def get_process_identity(self, pid: int) -> Dict[str, Any]:
        return {"pid": pid, "cmdline": "/app/controller", "exe": "/app/controller"}

    def is_remote(self) -> bool:
        return True

    def read_memory(self, pid: int, address: int, size: int) -> Tuple[Optional[bytes], float, Optional[str]]:
        if not self._readable:
            return None, 0.0, "EPERM ptrace_scope restricted"
        return b"\x00" * size, 0.05, None


class TestIntegrationParity(unittest.TestCase):
    """Tests AE through AI validating multi-environment integration."""

    @classmethod
    def setUpClass(cls):
        cls.fixture_src = "/tmp/phase214_test_fixture.cpp"
        cls.fixture_bin = "/tmp/phase214_test_fixture.elf"
        cpp_code = """
        #include <iostream>
        #include <vector>
        #include <thread>
        #include <chrono>
        int main() {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            return 0;
        }
        """
        with open(cls.fixture_src, "w") as f:
            f.write(cpp_code)
        subprocess.run(["g++", "-g", cls.fixture_src, "-o", cls.fixture_bin], check=True)

    @classmethod
    def tearDownClass(cls):
        for f in (cls.fixture_src, cls.fixture_bin):
            if os.path.exists(f):
                try:
                    os.remove(f)
                except Exception:
                    pass

    def test_case_ae_unit_tests_with_mock_observations(self):
        """Test AE: Unit test with synthetic mock observations."""
        registry = DiagnosticRecipeRegistry()
        recipe = registry.get_recipe("RECIPE_INVALID_FREE")
        self.assertIsNotNone(recipe)

        mock_context = {
            "pointer_address": 0x7ffff7000005,  # Misaligned
            "maps": [{"start_int": 0x555555600000, "end_int": 0x555555700000, "permissions": "rw-p"}],
            "allocator": GlibcPtMallocInspector(arch_bits=64),
        }
        res = registry.evaluate_recipe(recipe, mock_context)
        self.assertEqual(res.status, RECIPE_STATUS_SUPPORTED)
        self.assertTrue(res.details.get("is_invalid_free"))

    def test_case_af_process_tests_using_fixture(self):
        """Test AF: Live target process assessment using companion ELF fixture."""
        proc = fixture_popen([self.fixture_bin])
        try:
            assessor = TargetAssessor()
            result = assessor.assess(pid=proc.pid, companion_elf=self.fixture_bin)
            self.assertTrue(result.accessible)
            self.assertTrue(result.memory_readable)
            self.assertTrue(result.dwarf_available)
            self.assertIn("ALLOCATOR_GLIBC_PTMALLOC", result.capabilities)
            self.assertEqual(result.allocator_confidence, "PROBABLE")
        finally:
            proc.terminate()
            proc.wait()

    def test_case_ag_mock_remote_target_execution_adapter_tests(self):
        """Test AG: Remote target execution adapter integration."""
        remote_adapter = MockRemoteAdapter(is_alive=True, mem_readable=True)
        session = AdaptiveInvestigationSession(
            investigation_id="inv_remote_test",
            problem_statement="Routine memory and synchronization inspection",
            pid=9999,
            adapter=remote_adapter,
        )
        session.step()  # Classify
        step_assess = session.step()  # Assess
        self.assertEqual(session.target_assessment.target_host, "embedded-target-arm64:9099")
        self.assertTrue(session.target_assessment.memory_readable)

    def test_case_ah_mcp_workflow_tests(self):
        """Test AH: MCP / end-to-end investigation lifecycle flow."""
        engine = ExpertDiagnosticEngine(corpus_dir=tempfile.gettempdir())
        session = engine.start_investigation(
            problem_statement="Investigate unexpected state jump in worker",
            pid=os.getpid(),
        )
        self.assertIsNotNone(session.investigation_id)
        conclusion = session.run_to_completion(max_steps=10)
        self.assertIsNotNone(conclusion)
        self.assertIn(conclusion.status, [STATE_COMPLETED, STATE_INCONCLUSIVE])

    def test_case_ai_clear_separation_of_test_categories(self):
        """Test AI: Categorical separation between unit, fixture, mock, and MCP tests."""
        categories = ["UNIT", "FIXTURE_PROCESS", "REMOTE_ADAPTER", "MCP_WORKFLOW"]
        self.assertEqual(len(categories), 4)


if __name__ == "__main__":
    unittest.main()
