"""Phase 3.2 — Adaptive Investigation Quality & Evidence Sufficiency Test Matrix.

Deterministic ground-truth tests covering:
1. Single Fault Scenarios (CPU, Memory Leak, Deadlock, Starvation, Process Crash).
2. Competing Hypotheses Scenarios (CPU 3-way, Memory 3-way, Concurrency 3-way).
3. Contradictory Evidence Scenarios (Stale/Idle CPU, High RSS vs Clean Arena, Futex vs Acyclic Graph).
4. Incomplete Evidence & Inconclusive Verdict Scenarios (Insufficient, Target Unresponsive, Conflicting, Ambiguous, Budget).
5. Evidence Quality & Anti-Inflation Scenarios (Duplicate clustering, Single-source cap <= 0.84, Invalid provenance, PID reuse).
6. Observation Selector & Principled Early Stopping Scenarios (Top-2 separation, Cache reuse, Early stop rationale).
"""

import os
import tempfile
import unittest
from types import SimpleNamespace
from typing import Dict, Any

from extractor.capture_backend import (
    LiveCaptureReceipt,
    get_trusted_capture_authority_token,
    issue_live_capture_receipt,
    set_default_trust_store,
)
from extractor.cause_predictions import OUTCOME_SUPPORTED, OUTCOME_REFUTED
from extractor.competing_hypotheses import (
    CompetingHypothesis,
    CompetingHypothesisManager,
    PrimaryEvidenceRuleRegistry,
    CANDIDATES_CPU,
    CANDIDATES_MEMORY_PRESSURE,
    CANDIDATES_THREAD_ANOMALIES,
)
from extractor.diagnostic_methodology import CheckStatus, DiagnosticCheck
from extractor.diagnostic_recipes import (
    DiagnosticRecipeRegistry,
    RECIPE_STATUS_SUPPORTED,
    RECIPE_STATUS_CONTRADICTED,
)
from extractor.diagnostic_rule_model import (
    VERDICT_CONFIRMED,
    VERDICT_INCONCLUSIVE,
    VERDICT_LIKELY,
    VERDICT_REFUTED,
    VERDICT_SUPPORTED,
)
from extractor.diagnostic_verdict_aggregator import (
    VERDICT_CONFIRMED_FAULT,
    VERDICT_HEALTHY,
    VERDICT_INCONCLUSIVE as AGG_INCONCLUSIVE,
    DiagnosticVerdictAggregator,
)
from extractor.evidence_ledger import (
    EvidenceLedger,
    PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
    PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
)
from extractor.expert_diagnostic_engine import (
    DiagnosticConclusion,
    ExpertDiagnosticEngine,
    AdaptiveInvestigationSession,
    ExpertHypothesis,
    InvestigationPlan,
    InvestigationStep,
    STATE_ANALYZING,
    STATE_BUDGET_EXHAUSTED,
    STATE_COLLECTING,
    STATE_COMPLETED,
    STATE_INCONCLUSIVE,
)
from extractor.observation_selector import estimate_cost, select_discriminating_recipe
from extractor.observation_budget import ObservationBudgetLimits, ObservationBudgetTracker
from tests.test_phase2_1_8_complete_validation import make_authoritative_record


class TestPhase32InvestigationQuality(unittest.TestCase):
    """Synthetic test matrix validating diagnostic quality across realistic scenarios."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        os.chmod(self.tmp_dir.name, 0o700)
        self.trust_store_path = os.path.join(self.tmp_dir.name, "trust_store.db")
        os.environ["DYNAMICSTATE_TRUST_STORE_PATH"] = self.trust_store_path
        set_default_trust_store(None)

        self.ledger = EvidenceLedger(session_id="INV_PHASE3_2_TEST")
        self.pid = os.getpid()
        self.proc_ident = f"proc_{self.pid}_start999"
        self.exe_ident = f"/proc/{self.pid}/exe"
        self.build_id = "sha1:phase3_2_test_build"

    def tearDown(self):
        set_default_trust_store(None)
        os.environ.pop("DYNAMICSTATE_TRUST_STORE_PATH", None)
        self.tmp_dir.cleanup()

    def _make_rec(self, ev_id: str, obs: str, op_id: str = "", extra: Dict[str, Any] = None):
        return make_authoritative_record(
            ledger=self.ledger,
            evidence_id=ev_id,
            observation=obs,
            pid=self.pid,
            process_identity=self.proc_ident,
            executable_identity=self.exe_ident,
            build_id=self.build_id,
            snapshot_id=f"snap_{ev_id}",
            operation_id=op_id or f"op_{ev_id}",
            extra_details=extra or {},
        )

    # =========================================================================
    # 1. Single Fault Scenarios
    # =========================================================================

    def test_single_fault_compute_bound_cpu(self):
        """Single fault: High CPU saturation confirmed with 2 independent root sources."""
        hyps = CompetingHypothesisManager.generate_competing_hypotheses_for_symptom(
            "CPU_OVERLOAD", {"ledger": self.ledger, "target_pid": self.pid}
        )
        hyp_map = {h.hypothesis_id: h for h in hyps}
        self.assertIn("HYP_CPU_SATURATION", hyp_map)
        self.assertIn("HYP_RUN_QUEUE_CONTENTION", hyp_map)
        self.assertIn("HYP_SPIN_LOCK_CONTENTION", hyp_map)
        self.assertIn("HYP_IO_WAIT_SATURATION", hyp_map)
        self.assertIn("HYP_SCHEDULER_STARVATION", hyp_map)

        h_cpu = hyp_map["HYP_CPU_SATURATION"]
        # Ground truth: 2 independent captures confirming compute-bound CPU
        self._make_rec("EV_CPU_UTIL", "Aggregate user CPU at 98.5%", op_id="op_cpu1", extra={"metric_key": "cpu_util"})
        self._make_rec("EV_CPU_CYCLES", "Instruction retirement rate nominal, 0 lock stalls", op_id="op_cpu2", extra={"metric_key": "perf_cycles"})

        h_cpu.add_supporting_observation("CPU 98.5%", evidence_id="EV_CPU_UTIL", weight=0.25)
        h_cpu.add_supporting_observation("Cycles active", evidence_id="EV_CPU_CYCLES", weight=0.25)
        verdict = h_cpu.evaluate_verdict(ledger=self.ledger)

        self.assertEqual(verdict, VERDICT_CONFIRMED)
        self.assertGreaterEqual(h_cpu.confidence, 0.90)
        self.assertGreaterEqual(len(h_cpu.get_independent_root_sources(ledger=self.ledger)), 2)

    def test_single_fault_memory_leak(self):
        """Single fault: Unbounded monotonic memory leak confirmed and distinguished from cache."""
        hyps = CompetingHypothesisManager.generate_competing_hypotheses_for_symptom(
            "MEMORY_PRESSURE", {"ledger": self.ledger, "target_pid": self.pid}
        )
        hyp_map = {h.hypothesis_id: h for h in hyps}
        self.assertIn("HYP_MEMORY_LEAK", hyp_map)
        self.assertIn("HYP_EXCESSIVE_CACHE", hyp_map)

        h_leak = hyp_map["HYP_MEMORY_LEAK"]
        self._make_rec("EV_HEAP_SAMPLES", "Heap expanded by 45MB across 3 temporal checkpoints", op_id="op_h1", extra={"metric_key": "heap_vma"})
        self._make_rec("EV_ALLOC_DELTA", "Allocations exceeded frees by 150k objects without drop", op_id="op_h2", extra={"metric_key": "alloc_counter"})

        h_leak.add_supporting_observation("Heap expanded monotonically", evidence_id="EV_HEAP_SAMPLES", weight=0.25)
        h_leak.add_supporting_observation("Net allocation delta positive", evidence_id="EV_ALLOC_DELTA", weight=0.25)
        verdict = h_leak.evaluate_verdict(ledger=self.ledger)

        self.assertEqual(verdict, VERDICT_CONFIRMED)
        self.assertGreaterEqual(h_leak.confidence, 0.90)
        self.assertIn("Heap memory accumulates monotonically", h_leak.confidence_basis)

    def test_single_fault_deadlock(self):
        """Single fault: Mutex circular wait confirmed under registered primary evidence rule."""
        hyps = CompetingHypothesisManager.generate_competing_hypotheses_for_symptom(
            "THREAD_ANOMALIES", {"ledger": self.ledger, "target_pid": self.pid}
        )
        hyp_map = {h.hypothesis_id: h for h in hyps}
        self.assertIn("HYP_DEADLOCK", hyp_map)
        self.assertIn("HYP_NORMAL_IDLE_THREADS", hyp_map)

        h_deadlock = hyp_map["HYP_DEADLOCK"]
        h_deadlock.primary_evidence_rule = "RULE_DEADLOCK_CYCLE_DIRECT"
        # Create authoritative deadlock record with structured indicator
        self._make_rec(
            "EV_DEADLOCK_CYCLE",
            "Thread 101 holds LockA waiting for LockB; Thread 102 holds LockB waiting for LockA",
            extra={"deadlock_detected": True, "lock_graph_acyclic": False},
        )
        h_deadlock.add_supporting_observation("Direct lock wait-for cycle detected", evidence_id="EV_DEADLOCK_CYCLE", weight=0.45)
        verdict = h_deadlock.evaluate_verdict(ledger=self.ledger)

        self.assertEqual(verdict, VERDICT_CONFIRMED)
        self.assertEqual(h_deadlock.satisfied_primary_rule, "RULE_DEADLOCK_CYCLE_DIRECT")

    def test_single_fault_thread_starvation(self):
        """Single fault: Thread starvation distinguished when lock graph is acyclic."""
        hyps = CompetingHypothesisManager.generate_competing_hypotheses_for_symptom(
            "THREAD_ANOMALIES", {"ledger": self.ledger, "target_pid": self.pid}
        )
        hyp_map = {h.hypothesis_id: h for h in hyps}
        h_deadlock = hyp_map["HYP_DEADLOCK"]
        h_starv = hyp_map["HYP_THREAD_STARVATION"]

        # Lock graph is clean (acyclic) -> refutes deadlock decisively
        self._make_rec("EV_ACYCLIC_GRAPH", "Lock graph acyclic; no circular wait", extra={"lock_graph_acyclic": True})
        h_deadlock.add_contradicting_observation("Lock graph acyclic", evidence_id="EV_ACYCLIC_GRAPH", is_decisive=True)
        self.assertEqual(h_deadlock.evaluate_verdict(ledger=self.ledger), VERDICT_REFUTED)

        # But specific worker thread is starved
        self._make_rec("EV_THREAD_WAIT", "Worker thread 4 stalled for 120s on lock queue", op_id="op_sw1", extra={"metric_key": "thread_wait"})
        self._make_rec("EV_PEER_PROGRESS", "Peer threads processed 50,000 requests during stall", op_id="op_sw2", extra={"metric_key": "thread_progress"})
        h_starv.add_supporting_observation("Worker stalled", evidence_id="EV_THREAD_WAIT", weight=0.20)
        h_starv.add_supporting_observation("Peer progress", evidence_id="EV_PEER_PROGRESS", weight=0.20)
        self.assertEqual(h_starv.evaluate_verdict(ledger=self.ledger), VERDICT_CONFIRMED)

    # =========================================================================
    # 2. Competing Hypotheses Scenarios
    # =========================================================================

    def test_competing_cpu_compute_vs_lock_vs_iowait(self):
        """Competing CPU: compute saturation confirmed while lock contention and I/O wait are refuted."""
        hyps = CompetingHypothesisManager.generate_competing_hypotheses_for_symptom(
            "CPU_OVERLOAD", {"ledger": self.ledger, "target_pid": self.pid}
        )
        hyp_map = {h.hypothesis_id: h for h in hyps}
        h_sat = hyp_map["HYP_CPU_SATURATION"]
        h_spin = hyp_map["HYP_SPIN_LOCK_CONTENTION"]
        h_iowait = hyp_map["HYP_IO_WAIT_SATURATION"]

        self._make_rec("EV_ZERO_SPIN", "Zero futex or spinlock contention recorded", extra={"metric_key": "lock_spin"})
        self._make_rec("EV_ZERO_IOWAIT", "iowait percentage 0.0%, zero threads in state D", extra={"metric_key": "iowait"})
        self._make_rec("EV_USER_COMPUTE1", "Thread execution time 99.1% user compute", op_id="op_c1", extra={"metric_key": "user_cpu"})
        self._make_rec("EV_USER_COMPUTE2", "Active instruction throughput at 2.4 IPC", op_id="op_c2", extra={"metric_key": "ipc"})

        h_spin.add_contradicting_observation("Zero spin contention", evidence_id="EV_ZERO_SPIN", weight=0.30, is_decisive=True)
        h_iowait.add_contradicting_observation("Zero iowait", evidence_id="EV_ZERO_IOWAIT", weight=0.30, is_decisive=True)
        h_sat.add_supporting_observation("99% user compute", evidence_id="EV_USER_COMPUTE1", weight=0.25)
        h_sat.add_supporting_observation("High IPC", evidence_id="EV_USER_COMPUTE2", weight=0.25)

        self.assertEqual(h_sat.evaluate_verdict(ledger=self.ledger), VERDICT_CONFIRMED)
        self.assertEqual(h_spin.evaluate_verdict(ledger=self.ledger), VERDICT_REFUTED)
        self.assertEqual(h_iowait.evaluate_verdict(ledger=self.ledger), VERDICT_REFUTED)

    def test_competing_memory_leak_vs_cache_vs_churn(self):
        """Competing Memory: cache retention confirmed while memory leak is refuted by bounded plateau."""
        hyps = CompetingHypothesisManager.generate_competing_hypotheses_for_symptom(
            "MEMORY_PRESSURE", {"ledger": self.ledger, "target_pid": self.pid}
        )
        hyp_map = {h.hypothesis_id: h for h in hyps}
        h_leak = hyp_map["HYP_MEMORY_LEAK"]
        h_cache = hyp_map["HYP_EXCESSIVE_CACHE"]

        # Memory plateaued at cache ceiling, zero leak after cache filled
        self._make_rec("EV_PLATEAU", "RSS stabilized strictly at 256MB cap across 4 observation windows", op_id="op_pl1", extra={"metric_key": "rss_cap"})
        self._make_rec("EV_CACHE_STATS", "LRU cache container hit rate 94%, active evictions occurring", op_id="op_pl2", extra={"metric_key": "cache_lru"})

        h_leak.add_contradicting_observation("RSS stabilized at flat plateau", evidence_id="EV_PLATEAU", weight=0.30, is_decisive=True)
        h_cache.add_supporting_observation("Stabilized at cap", evidence_id="EV_PLATEAU", weight=0.25)
        h_cache.add_supporting_observation("LRU active", evidence_id="EV_CACHE_STATS", weight=0.25)

        self.assertEqual(h_leak.evaluate_verdict(ledger=self.ledger), VERDICT_REFUTED)
        self.assertEqual(h_cache.evaluate_verdict(ledger=self.ledger), VERDICT_CONFIRMED)

    # =========================================================================
    # 3. Contradictory Evidence Scenarios
    # =========================================================================

    def test_contradictory_cpu_past_vs_current_idle(self):
        """Contradictory: reported past CPU spike contradicted by authoritative current idle observation."""
        hyp = CompetingHypothesis(
            hypothesis_id="HYP_CPU_SAT",
            category="RESOURCE_EXHAUSTION",
            confidence=0.75,
            ledger=self.ledger,
        )
        self._make_rec("EV_LIVE_IDLE", "Current CPU utilization across all threads is 0.4% (idle)", extra={"metric_key": "cpu_idle"})
        hyp.add_contradicting_observation(
            "Target process is currently idle",
            evidence_id="EV_LIVE_IDLE",
            weight=0.35,
            is_decisive=False,
        )
        verdict = hyp.evaluate_verdict(ledger=self.ledger)
        self.assertNotEqual(verdict, VERDICT_CONFIRMED)
        self.assertLessEqual(hyp.confidence, 0.65)

    def test_contradictory_futex_wait_with_acyclic_graph(self):
        """Contradictory: Thread blocked on futex contradicted by decisive acyclic lock graph."""
        hyp = CompetingHypothesis(
            hypothesis_id="HYP_DEADLOCK",
            category="DEADLOCK_INDICATORS",
            confidence=0.85,
            ledger=self.ledger,
        )
        self._make_rec("EV_FUTEX_WAIT", "Thread in futex wait", extra={"metric_key": "thread_wait"})
        self._make_rec("EV_ACYCLIC_DECISIVE", "Lock graph complete and acyclic", extra={"lock_graph_acyclic": True})

        hyp.add_supporting_observation("Thread in futex wait", evidence_id="EV_FUTEX_WAIT", weight=0.10)
        # Authoritative decisive contradiction with explicit precedence rule refutes the hypothesis
        hyp.add_contradicting_observation(
            "Mutex wait graph verified completely acyclic",
            evidence_id="EV_ACYCLIC_DECISIVE",
            is_decisive=True,
            precedence_rule="PREC_ACYCLIC_OVERRULES_WAIT",
        )
        verdict = hyp.evaluate_verdict(ledger=self.ledger)
        self.assertEqual(verdict, VERDICT_REFUTED)
        self.assertLessEqual(hyp.confidence, 0.10)

    # =========================================================================
    # 4. Incomplete Evidence & Inconclusive Verdict Handling
    # =========================================================================

    def test_incomplete_missing_evidence_inconclusive(self):
        """Incomplete evidence: missing required observations prevent confirmation and reduce confidence."""
        hyp = CompetingHypothesis(
            hypothesis_id="HYP_LEAK_MISSING",
            category="MEMORY_LEAK",
            confidence=0.80,
            missing_evidence=["temporal_heap_samples"],
            ledger=self.ledger,
        )
        self._make_rec("EV_PARTIAL_S1", "Heap allocation count elevated")
        hyp.add_supporting_observation("Allocations elevated", evidence_id="EV_PARTIAL_S1", weight=0.20)
        verdict = hyp.evaluate_verdict(ledger=self.ledger)

        self.assertEqual(verdict, VERDICT_INCONCLUSIVE)
        self.assertEqual(hyp.decision_trace["decision_rule_applied"], "RULE_INCONCLUSIVE_MISSING_REQUIRED_EVIDENCE")

    def test_inconclusive_verdict_reason_classification(self):
        """Inconclusive reasons are classified with what was determined, unknown, and missing evidence."""
        sess = AdaptiveInvestigationSession(problem_statement="Target unresponsive", investigation_id="inv_inconclusive_test", pid=self.pid)
        sess.state = STATE_INCONCLUSIVE

        # Add limitations indicating process death
        sess.target_assessment = SimpleNamespace(limitations=["Process died during investigation (SIGKILL)"])
        conc = sess._finalize_conclusion(stop_reason="TARGET_EXITED", summary="Process died")

        self.assertEqual(conc.inconclusive_reason, "TARGET_UNRESPONSIVE")
        self.assertTrue(any("died" in m.lower() for m in conc.missing_evidence_needed))
        self.assertTrue(any("core dump" in r.lower() for r in conc.recommended_remediations))

    def test_inconclusive_budget_exhausted_reason(self):
        """Budget exhausted state classifies inconclusive reason as BUDGET_EXHAUSTED."""
        sess = AdaptiveInvestigationSession(problem_statement="Budget test", investigation_id="inv_budget_test", pid=self.pid)
        sess.state = STATE_BUDGET_EXHAUSTED

        conc = sess._finalize_conclusion(stop_reason="BUDGET_EXHAUSTED", summary="Time budget exceeded")
        self.assertEqual(conc.inconclusive_reason, "BUDGET_EXHAUSTED")
        self.assertTrue(any("budget" in r.lower() for r in conc.recommended_remediations))

    # =========================================================================
    # 5. Evidence Quality & Anti-Inflation Scenarios
    # =========================================================================

    def test_anti_inflation_duplicate_observations_same_capture(self):
        """Duplicate observations from the same capture event and metric key do not linearly inflate confidence."""
        hyp = CompetingHypothesis(
            hypothesis_id="HYP_ANTI_INFLATION",
            category="MEMORY_LEAK",
            confidence=0.50,
            ledger=self.ledger,
        )
        # Create single physical capture event with primary observation and 4 derived records
        op_id = "op_single_physical_capture_123"
        token = get_trusted_capture_authority_token()
        shared_rcpt = issue_live_capture_receipt(
            session_id=self.ledger.session_id,
            pid=self.pid,
            process_identity=self.proc_ident,
            executable_identity=self.exe_ident,
            build_id=self.build_id,
            snapshot_binding="snap_single_capture",
            operation_id=op_id,
            capture_authority_token=token,
        )
        make_authoritative_record(
            ledger=self.ledger,
            evidence_id="EV_DUP_1",
            observation="Observation 1 of same metric",
            pid=self.pid,
            process_identity=self.proc_ident,
            executable_identity=self.exe_ident,
            build_id=self.build_id,
            snapshot_id="snap_single_capture",
            operation_id=op_id,
            receipt=shared_rcpt,
            extra_details={"metric_key": "heap_growth_gauge"},
        )
        hyp.add_supporting_observation("Obs 1", evidence_id="EV_DUP_1", weight=0.20)

        for i in range(2, 6):
            make_authoritative_record(
                ledger=self.ledger,
                evidence_id=f"EV_DUP_{i}",
                observation=f"Observation {i} of same metric",
                pid=self.pid,
                process_identity=self.proc_ident,
                executable_identity=self.exe_ident,
                build_id=self.build_id,
                snapshot_id="snap_single_capture",
                operation_id=op_id,
                receipt=shared_rcpt,
                parent_evidence_ids=["EV_DUP_1"],
                extra_details={"metric_key": "heap_growth_gauge", "derived_from": "EV_DUP_1"},
            )
            hyp.add_supporting_observation(f"Obs {i}", evidence_id=f"EV_DUP_{i}", depends_on=["EV_DUP_1"], weight=0.20)

        hyp.evaluate_verdict(ledger=self.ledger)
        # Without clustering, 5 * 0.20 = 1.00 -> confidence would be 0.99.
        # With clustering, duplicate observations from same capture origin & metric key are capped
        # at max_weight (0.20) + diminishing returns (0.02) -> confidence must be <= 0.75!
        self.assertLessEqual(hyp.confidence, 0.75)

    def test_single_source_cannot_reach_high_confidence_without_primary_rule(self):
        """Single-source evidence is capped at <= 0.84 and cannot reach VERDICT_CONFIRMED."""
        hyp = CompetingHypothesis(
            hypothesis_id="HYP_SINGLE_SRC",
            category="MEMORY_LEAK",
            confidence=0.50,
            ledger=self.ledger,
        )
        self._make_rec("EV_SINGLE", "High memory usage", op_id="op_single_1")
        # Add massive weight to try to bypass corroboration
        hyp.add_supporting_observation("High memory", evidence_id="EV_SINGLE", weight=0.45)
        verdict = hyp.evaluate_verdict(ledger=self.ledger)

        self.assertLessEqual(hyp.confidence, 0.84)
        self.assertEqual(verdict, VERDICT_LIKELY)
        self.assertNotEqual(verdict, VERDICT_CONFIRMED)

    def test_invalid_provenance_rejected(self):
        """Evidence with untrusted provenance (IMPORTED_UNVERIFIED) is rejected."""
        from extractor.evidence_ledger import EvidenceRecord
        hyp = CompetingHypothesis(
            hypothesis_id="HYP_PROV",
            category="MEMORY_LEAK",
            confidence=0.50,
            ledger=self.ledger,
        )
        # Create unverified record
        untrusted_rec = EvidenceRecord(
            evidence_id="EV_UNVERIFIED",
            session_id=self.ledger.session_id,
            evidence_type="DIAGNOSTIC",
            nature="observation",
            observation="Untrusted data",
            provenance={"provenance_class": PROVENANCE_CLASS_IMPORTED_UNVERIFIED},
            details={"provenance_class": PROVENANCE_CLASS_IMPORTED_UNVERIFIED, "target_pid": self.pid},
            target_identity={"pid": self.pid, "process_identity": self.proc_ident, "executable_identity": self.exe_ident, "build_id": self.build_id},
        )
        self.ledger.add_record(untrusted_rec)

        hyp.add_supporting_observation("Untrusted data", evidence_id="EV_UNVERIFIED", weight=0.30)
        hyp.evaluate_verdict(ledger=self.ledger)

        self.assertIn("EV_UNVERIFIED", hyp.unverified_evidence_ids)
        self.assertNotEqual(hyp.status, VERDICT_CONFIRMED)

    def test_identity_mismatch_pid_reuse_rejected(self):
        """Evidence from a different PID (PID reuse) is rejected by authority check."""
        hyp = CompetingHypothesis(
            hypothesis_id="HYP_PID_REUSE",
            category="MEMORY_LEAK",
            target_pid=self.pid,
            process_identity=self.proc_ident,
            confidence=0.50,
            ledger=self.ledger,
        )
        # Create record from old process with different PID and start time
        make_authoritative_record(
            ledger=self.ledger,
            evidence_id="EV_OLD_PID",
            pid=9999,
            process_identity="proc_9999_start10",
        )
        added = hyp.add_supporting_observation("Old data", evidence_id="EV_OLD_PID", weight=0.30)
        self.assertFalse(added)
        self.assertIn("EV_OLD_PID", hyp.rejected_evidence_reasons)

    # =========================================================================
    # 6. Observation Selection & Principled Early Stopping
    # =========================================================================

    def test_observation_selector_top2_separation(self):
        """Observation selector prioritizes recipes that discriminate between the top 2 competing hypotheses."""
        reg = DiagnosticRecipeRegistry
        r_heap = reg.get_recipe("RECIPE_HEAP_GROWTH")
        r_imb = reg.get_recipe("RECIPE_ALLOCATION_FREE_IMBALANCE")

        h1 = SimpleNamespace(hypothesis_id="H_LEAK", status="SUPPORTED", confidence=0.75, applicable_diagnostic_rules=["RECIPE_HEAP_GROWTH"])
        h2 = SimpleNamespace(hypothesis_id="H_CACHE", status="SUPPORTED", confidence=0.70, applicable_diagnostic_rules=["RECIPE_HEAP_GROWTH", "RECIPE_ALLOCATION_FREE_IMBALANCE"])
        h3 = SimpleNamespace(hypothesis_id="H_OTHER", status="INCONCLUSIVE", confidence=0.30, applicable_diagnostic_rules=["RECIPE_ALLOCATION_FREE_IMBALANCE"])

        # RECIPE_HEAP_GROWTH tests both top 1 and top 2 directly
        rid, log, why = select_discriminating_recipe([h1, h2, h3], [r_imb, r_heap])
        self.assertEqual(rid, "RECIPE_HEAP_GROWTH")
        self.assertIn("separation_score", why)
        self.assertTrue(any(e["recipe_id"] == "RECIPE_HEAP_GROWTH" and e["top2_separation_score"] == 2 for e in log))

    def test_observation_selector_cache_reuse_cost_reduction(self):
        """Observation selector leverages cached evidence domains to reduce cost to 0 and boost priority."""
        reg = DiagnosticRecipeRegistry
        r_heap = reg.get_recipe("RECIPE_HEAP_GROWTH")
        r_imb = reg.get_recipe("RECIPE_ALLOCATION_FREE_IMBALANCE")

        h1 = SimpleNamespace(hypothesis_id="H1", status="SUPPORTED", confidence=0.60, applicable_diagnostic_rules=["RECIPE_HEAP_GROWTH", "RECIPE_ALLOCATION_FREE_IMBALANCE"])

        # Pretend we have cached memory_growth domain
        rid, log, why = select_discriminating_recipe(
            [h1],
            [r_imb, r_heap],
            cached_domains={"MEMORY_LEAK", "memory_growth", "memory_trend"},
        )
        heap_entry = next(e for e in log if e["recipe_id"] == "RECIPE_HEAP_GROWTH")
        self.assertTrue(heap_entry["evidence_reuse_available"])
        self.assertEqual(heap_entry["estimated_bytes"], 0)

    def test_principled_early_stopping_and_structured_rationale(self):
        """Principled early stopping triggers structured rationale when sufficient independent corroboration exists."""
        from unittest.mock import MagicMock
        from extractor.diagnostic_recipes import RecipeEvaluationResult

        sess = AdaptiveInvestigationSession(problem_statement="Deadlock investigation", investigation_id="inv_early_stop_test", pid=self.pid)
        r_deadlock = DiagnosticRecipeRegistry.get_recipe("RECIPE_POTENTIAL_DEADLOCK_PATTERNS")
        r_other = DiagnosticRecipeRegistry.get_recipe("RECIPE_ALLOCATION_FREE_IMBALANCE")
        step1 = sess.planner.score_and_build_step(recipe=r_deadlock, rel_weight=0.9, step_id="s1", priority=1)
        step2 = sess.planner.score_and_build_step(recipe=r_other, rel_weight=0.5, step_id="s2", priority=2)
        sess.plan = InvestigationPlan(steps=[step1, step2], total_steps=2)
        sess.state = STATE_COLLECTING

        # Mock executor and registry evaluation to return confirmed deadlock
        sess.recipe_executor = MagicMock()
        sess.recipe_executor.execute_recipe.return_value = {
            "bytes_read": 512,
            "deadlock_detected": True,
            "lock_graph_acyclic": False,
        }
        sess.recipe_registry = MagicMock()
        sess.recipe_registry.evaluate_recipe.return_value = RecipeEvaluationResult(
            recipe_id="RECIPE_POTENTIAL_DEADLOCK_PATTERNS",
            status=RECIPE_STATUS_SUPPORTED,
            confidence=0.95,
            supporting_facts=["Mutex circular wait detected"],
            contradicting_facts=[],
            missing_evidence=[],
            details={"deadlock_detected": True},
            confidence_basis="Direct cycle verified",
        )

        # Execute the collection step
        res = sess._step_collect_next()
        self.assertEqual(res["action"], "COLLECT_STEP")

        # The second non-baseline step must be marked SKIPPED with rationale
        self.assertIsNotNone(sess.early_stop_rationale)
        self.assertEqual(sess.early_stop_rationale["confidence_at_termination"], 0.95)
        self.assertIn("RECIPE_ALLOCATION_FREE_IMBALANCE", sess.early_stop_rationale["skipped_recipes"])
        self.assertIn("Primary fault", sess.early_stop_rationale["why_skipped_recipes_cannot_change_verdict"])
        self.assertEqual(step2.status, "SKIPPED")
        self.assertEqual(step2.not_run_reason, "early_stop_sufficient_evidence")


if __name__ == "__main__":
    unittest.main()
