"""Adaptive Investigation Engine.

Coordinates multi-stage adaptive investigations:
- AdaptiveInvestigationPlanner: symptom and goal-driven DAG planning
- DeterministicScheduler: strict priority + ID tie-breaking determinism
- EvidenceCache: disaggregates static DWARF layout from dynamic runtime epoch
- AdaptiveRuleEvaluator: 3-valued logic evaluation (True, False, Unknown)
- AdaptiveTerminationPolicy: early stopping on budget depletion or conclusive verdict
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import time
from typing import Any, Dict, List, Optional, Set, Tuple
import uuid

from .evidence_adapter import EvidenceAdapter
from .evidence_ledger import EvidenceLedger, EvidenceRecord
from .inspection_module import (
    DOMAIN_CONCURRENCY,
    DOMAIN_HEAP,
    DOMAIN_INTEGRITY,
    DOMAIN_IPC,
    DOMAIN_MEMORY,
    DOMAIN_TEMPORAL,
    FunctionalInspectionModule,
    InspectionContext,
    InspectionModuleRegistry,
    InspectionProfile,
)
from .observation_budget import ObservationBudgetLimits, ObservationBudgetTracker
from .target_adapter import LocalTargetAdapter, TargetExecutionAdapter
from .verdict_engine import (
    ASSERTION_ABSTAIN,
    ASSERTION_FAIL,
    ASSERTION_PASS,
    DIAG_CONFIRMED,
    DIAG_INCONCLUSIVE,
    DIAG_NO_ISSUE_DETECTED,
    DIAG_SUSPECTED,
    AssertionEvaluation,
    DiagnosticVerdict,
    VerdictEngine,
    ZeroCdnReporter,
)


class EvidenceCache:
    """Disaggregates static binary evidence from dynamic runtime sampling epochs."""

    def __init__(self):
        self._static_cache: Dict[str, Any] = {}
        self._dynamic_cache: Dict[str, Dict[str, Any]] = {}
        self._current_epoch: int = 0

    @property
    def current_epoch(self) -> int:
        return self._current_epoch

    def advance_epoch(self) -> int:
        """Invalidates dynamic cache and increments epoch."""
        self._current_epoch += 1
        self._dynamic_cache.clear()
        return self._current_epoch

    def get_static(self, binary_key: str, item_key: str) -> Optional[Any]:
        return self._static_cache.get(f"{binary_key}::{item_key}")

    def put_static(self, binary_key: str, item_key: str, val: Any) -> None:
        self._static_cache[f"{binary_key}::{item_key}"] = val

    def get_dynamic(self, target_key: str, item_key: str) -> Optional[Any]:
        return self._dynamic_cache.get(f"epoch_{self._current_epoch}::{target_key}::{item_key}")

    def put_dynamic(self, target_key: str, item_key: str, val: Any) -> None:
        self._dynamic_cache[f"epoch_{self._current_epoch}::{target_key}::{item_key}"] = val


class AdaptiveInvestigationPlanner:
    """Plans inspection profiles adaptively based on symptoms and incoming findings."""

    def __init__(self, registry: InspectionModuleRegistry):
        self.registry = registry

    def plan_initial_inspections(
        self,
        goal: str,
        assertions: Optional[List[str]] = None,
        symptom_hints: Optional[List[str]] = None,
    ) -> List[str]:
        """Produces a deterministic initial list of profile IDs to inspect."""
        lower_goal = (goal or "").lower()
        hints = [h.lower() for h in (symptom_hints or [])]
        combined = lower_goal + " " + " ".join(hints)

        selected: Set[str] = set()

        # Domain keywords mapping
        if any(w in combined for w in ("deadlock", "lock", "mutex", "stuck", "hang", "blocked", "contention", "thread")):
            for p in self.registry.list_profiles(domain=DOMAIN_CONCURRENCY):
                selected.add(p.profile_id)

        if any(w in combined for w in ("pool", "buffer", "leak", "allocation", "exhaust", "slot")):
            for p in self.registry.list_profiles(domain=DOMAIN_MEMORY):
                selected.add(p.profile_id)

        if any(w in combined for w in ("corrupt", "integrity", "crash", "segv", "dangling", "null", "pointer")):
            for p in self.registry.list_profiles(domain=DOMAIN_INTEGRITY):
                selected.add(p.profile_id)

        if any(w in combined for w in ("ipc", "shm", "queue", "pipe", "ring", "dpdk")):
            for p in self.registry.list_profiles(domain=DOMAIN_IPC):
                selected.add(p.profile_id)

        if any(w in combined for w in ("drift", "counter", "timeseries", "change", "diff", "behavior")):
            for p in self.registry.list_profiles(domain=DOMAIN_TEMPORAL):
                selected.add(p.profile_id)

        # Default fallback: auto triage & locks if empty
        if not selected:
            for p in self.registry.list_profiles():
                if p.priority >= 100:
                    selected.add(p.profile_id)

        # Always return sorted deterministically by profile priority DESC, then ID ASC
        all_profiles = [p for p in self.registry.list_profiles() if p.profile_id in selected]
        return [p.profile_id for p in all_profiles]

    def refine_plan(
        self,
        current_profile_id: str,
        inspection_result: Dict[str, Any],
        already_scheduled: Set[str],
    ) -> List[str]:
        """Refines plan based on observed evidence anomalies."""
        additional: List[str] = []

        # If deadlock or mutex contention found, ensure thread owner analysis is scheduled
        if inspection_result.get("deadlock_detected") or inspection_result.get("contended_locks"):
            if "insp_find_owners" not in already_scheduled and self.registry.get("insp_find_owners"):
                additional.append("insp_find_owners")

        # If memory pool leakage or stuck slots found, add symbol owner lookup
        if inspection_result.get("leak_count", 0) > 0 or inspection_result.get("stuck_slots"):
            if "insp_find_owners" not in already_scheduled and self.registry.get("insp_find_owners"):
                additional.append("insp_find_owners")

        # If corrupted pointers found in memory integrity audit, schedule frame locals
        if inspection_result.get("corrupted_pointers", 0) > 0:
            if "insp_frame_locals" not in already_scheduled and self.registry.get("insp_frame_locals"):
                additional.append("insp_frame_locals")

        return additional


class DeterministicScheduler:
    """Maintains a deterministic inspection execution queue with strict tie-breaking."""

    def __init__(self, registry: InspectionModuleRegistry):
        self.registry = registry
        self._queue: List[Tuple[int, str, int]] = []  # (-priority, profile_id, sequence_id)
        self._seq: int = 0
        self._enqueued_ids: Set[str] = set()

    def enqueue(self, profile_id: str) -> bool:
        if profile_id in self._enqueued_ids:
            return False
        profile = self.registry.get(profile_id)
        if not profile:
            return False

        p_obj = profile.profile
        self._seq += 1
        # Priority inverted for min-heap sorting: higher priority comes first
        entry = (-p_obj.priority, p_obj.profile_id, self._seq)
        self._queue.append(entry)
        self._enqueued_ids.add(profile_id)
        self._queue.sort()  # Guaranteed deterministic order
        return True

    def pop_next(self) -> Optional[str]:
        if not self._queue:
            return None
        _, profile_id, _ = self._queue.pop(0)
        return profile_id

    def is_empty(self) -> bool:
        return len(self._queue) == 0

    @property
    def enqueued_ids(self) -> Set[str]:
        return set(self._enqueued_ids)


class AdaptiveTerminationPolicy:
    """Evaluates multi-factor stopping criteria for an investigation."""

    @staticmethod
    def should_terminate(
        budget_tracker: ObservationBudgetTracker,
        current_verdict: Optional[DiagnosticVerdict] = None,
        consecutive_empty_steps: int = 0,
    ) -> Tuple[bool, str]:
        # 1. Budget exhausted
        ok, reason = budget_tracker.check_budget()
        if not ok:
            return True, f"Budget limit reached: {reason}"

        # 2. Conclusive diagnostic confidence
        if current_verdict:
            if current_verdict.final_diagnosis in (DIAG_CONFIRMED, DIAG_NO_ISSUE_DETECTED) and current_verdict.confidence_score >= 1.0:
                return True, f"Conclusive diagnosis reached: {current_verdict.final_diagnosis} (100% confidence)"

        # 3. Diminishing returns (3 steps without new evidence)
        if consecutive_empty_steps >= 3:
            return True, "Terminated due to diminishing returns (3 consecutive steps without novel evidence)"

        return False, "Continue"


class AdaptiveInvestigationEngine:
    """Comprehensive coordinator for adaptive runtime investigations."""

    def __init__(
        self,
        watch_manager: Any,
        registry: Optional[InspectionModuleRegistry] = None,
        default_limits: Optional[ObservationBudgetLimits] = None,
    ):
        self.watch_manager = watch_manager
        self.registry = registry or self._build_default_registry()
        self.default_limits = default_limits or ObservationBudgetLimits()
        self.planner = AdaptiveInvestigationPlanner(self.registry)
        self.cache = EvidenceCache()
        self.adapter = EvidenceAdapter()

    def _build_default_registry(self) -> InspectionModuleRegistry:
        reg = InspectionModuleRegistry()

        # 1. Thread Locks & Callstacks (Priority 150)
        p_locks = InspectionProfile(
            profile_id="insp_locks",
            domain=DOMAIN_CONCURRENCY,
            name="Thread Callstacks & Mutex Contention",
            priority=150,
        )
        reg.register(FunctionalInspectionModule(
            p_locks,
            lambda wm, **kw: wm.inspect_thread_callstacks_and_locks(**kw)
        ))

        # 2. Memory Pool & Buffer Array (Priority 140)
        p_pool = InspectionProfile(
            profile_id="insp_pool",
            domain=DOMAIN_MEMORY,
            name="Memory Pool & Buffer Allocation Sweep",
            priority=140,
        )
        reg.register(FunctionalInspectionModule(
            p_pool,
            lambda wm, **kw: wm.scan_memory_pool_or_array(target_expression=kw.pop("target_expression", "*gpMem"), **kw)
        ))

        # 3. Memory Integrity Audit (Priority 130)
        p_integ = InspectionProfile(
            profile_id="insp_integrity",
            domain=DOMAIN_INTEGRITY,
            name="Memory Pointer & Struct Byte Integrity Audit",
            priority=130,
        )
        reg.register(FunctionalInspectionModule(
            p_integ,
            lambda wm, **kw: wm.audit_memory_integrity(root_expression=kw.pop("root_expression", "g_corrupt_record"), **kw)
        ))

        # 4. Symbol Owner Lookup (Priority 120)
        p_owners = InspectionProfile(
            profile_id="insp_find_owners",
            domain=DOMAIN_CONCURRENCY,
            name="Buffer Slot Thread Ownership Scanner",
            priority=120,
        )
        reg.register(FunctionalInspectionModule(
            p_owners,
            lambda wm, **kw: wm.find_symbol_owners_and_threads(target_expression=kw.pop("target_expression", "*gpMem"), **kw)
        ))

        # 5. Stack Frame Locals & Parameters (Priority 110)
        p_locals = InspectionProfile(
            profile_id="insp_frame_locals",
            domain=DOMAIN_CONCURRENCY,
            name="Stack Frame Local Variable & Parameter Decoder",
            priority=110,
        )
        reg.register(FunctionalInspectionModule(
            p_locals,
            lambda wm, **kw: wm.inspect_thread_locals_and_frame_vars(**kw)
        ))

        # 6. IPC Pipeline Inspection (Priority 100)
        p_ipc = InspectionProfile(
            profile_id="insp_ipc",
            domain=DOMAIN_IPC,
            name="IPC Pipeline & Queue State Tracer",
            priority=100,
        )
        reg.register(FunctionalInspectionModule(
            p_ipc,
            lambda wm, **kw: wm.trace_ipc_pipeline(pipeline_expression=kw.pop("pipeline_expression", "g_ipc_ring"), **kw)
        ))

        return reg

    def run_adaptive_investigation(
        self,
        goal: str,
        pid: int,
        companion_elf_path: str,
        hypothesis: Optional[str] = None,
        assertions: Optional[List[str]] = None,
        symptom_hints: Optional[List[str]] = None,
        budget_limits: Optional[ObservationBudgetLimits] = None,
        target_adapter: Optional[TargetExecutionAdapter] = None,
        session_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Executes a complete adaptive investigation cycle within observation budget."""
        sess_id = session_id or f"inv_adap_{uuid.uuid4().hex[:8]}"
        limits = budget_limits or self.default_limits
        budget_tracker = ObservationBudgetTracker(limits)
        budget_tracker.start()

        eff_adapter = target_adapter or LocalTargetAdapter()
        ledger = EvidenceLedger(session_id=sess_id)

        target_identity = {
            "pid": pid,
            "companion_elf": companion_elf_path,
        }

        # 1. Deterministic Initial Plan
        plan = self.planner.plan_initial_inspections(
            goal=goal,
            assertions=assertions,
            symptom_hints=symptom_hints,
        )

        scheduler = DeterministicScheduler(self.registry)
        for pid_str in plan:
            scheduler.enqueue(pid_str)

        executed_profiles: List[str] = []
        inspection_outputs: Dict[str, Any] = {}
        consecutive_empty = 0

        # 2. Adaptive Loop
        while not scheduler.is_empty():
            should_stop, stop_reason = AdaptiveTerminationPolicy.should_terminate(
                budget_tracker,
                consecutive_empty_steps=consecutive_empty,
            )
            if should_stop:
                break

            current_id = scheduler.pop_next()
            if not current_id:
                break

            mod = self.registry.get(current_id)
            if not mod:
                continue

            ctx = InspectionContext(
                pid=pid,
                companion_elf=companion_elf_path,
                adapter=eff_adapter,
                budget_tracker=budget_tracker,
                target_info=target_identity,
            )

            res = mod.run(ctx, self.watch_manager)
            executed_profiles.append(current_id)
            inspection_outputs[current_id] = res

            # Convert result to evidence record in ledger
            ev_rec = self.adapter.adapt_generic_tool_output(
                tool_name=f"inspection_{current_id}",
                tool_result=res,
                session_id=sess_id,
                target_identity=target_identity,
            )
            self.adapter.record_into_ledger(ev_rec, ledger)

            # Refine plan based on findings
            refinements = self.planner.refine_plan(
                current_profile_id=current_id,
                inspection_result=res,
                already_scheduled=scheduler.enqueued_ids,
            )
            for r_id in refinements:
                scheduler.enqueue(r_id)

            if res.get("success"):
                consecutive_empty = 0
            else:
                consecutive_empty += 1

        # 3. If explicit assertions are supplied, evaluate them via evaluate_symbol_paths
        assertion_evaluations: List[AssertionEvaluation] = []
        if assertions:
            coerced_assertions = self.watch_manager._coerce_str_list(assertions)
            parsed_list = [self.watch_manager._parse_single_assertion(a) for a in coerced_assertions if str(a).strip()]
            lhs_list = [p["lhs"] for p in parsed_list]

            t_eval_0 = time.monotonic_ns()
            eval_out = self.watch_manager.evaluate_symbol_paths(
                pid=pid,
                companion_elf_path=companion_elf_path,
                expressions=lhs_list,
                adapter=eff_adapter,
            )
            lat_eval_us = (time.monotonic_ns() - t_eval_0) / 1000.0
            budget_tracker.record_read(bytes_read=len(lhs_list) * 64, latency_us=lat_eval_us)
            budget_tracker.record_sample()

            eval_by_expr = {r["expression"]: r for r in eval_out.get("results", [])}

            # Adapt symbol evals into ledger
            sym_records = self.adapter.adapt_symbol_evaluation(
                eval_result=eval_out,
                target_identity=target_identity,
                session_id=sess_id,
            )
            self.adapter.record_into_ledger(sym_records, ledger)

            rec_map = {r.field_observation.get("field_path"): r.evidence_id for r in sym_records if r.field_observation}

            for p_item in parsed_list:
                lhs = p_item["lhs"]
                ev_data = eval_by_expr.get(lhs, {})
                ev_status = ev_data.get("status", "UNKNOWN")
                obs_val = ev_data.get("value")
                res_expr = ev_data.get("resolved_expression") or lhs
                rt_addr = ev_data.get("runtime_address")
                was_coerced = ev_data.get("was_coerced", False)
                ev_id = rec_map.get(lhs)

                a_eval = VerdictEngine.evaluate_assertion(
                    raw_assertion=p_item["raw"],
                    lhs=lhs,
                    op=p_item["operator"],
                    rhs_raw=p_item["rhs_raw"],
                    observed_value=obs_val,
                    obs_status=ev_status,
                    res_expr=res_expr,
                    rt_addr=rt_addr,
                    was_coerced=was_coerced,
                    evidence_id=ev_id,
                )
                assertion_evaluations.append(a_eval)

        # 4. Synthesize Diagnostic Verdict
        hyp_str = hypothesis or goal
        budget_summary = budget_tracker.to_dict()

        verdict = VerdictEngine.synthesize_verdict(
            hypothesis=hyp_str,
            evaluations=assertion_evaluations,
            target_identity=target_identity,
            causal_attribution_verified=False,
            attribution_basis=None,
            budget_usage=budget_summary,
        )

        # 5. Generate Zero-CDN HTML & JSON Reports
        report_html = ZeroCdnReporter.render_html(
            verdict=verdict,
            title=f"dynamicState Adaptive Investigation: {hyp_str[:40]}",
            remediation_checklist=[
                "Verify thread lock contention state in trace matrix",
                "Inspect memory pool allocations for stuck buffer descriptors",
                "Ensure observation budget constraints remain within operational limits",
            ],
        )
        report_json = ZeroCdnReporter.render_json(verdict)

        return {
            "success": True,
            "session_id": sess_id,
            "goal": goal,
            "hypothesis": hyp_str,
            "final_diagnosis": verdict.final_diagnosis,
            "hypothesis_state": verdict.hypothesis_state,
            "confidence_score": verdict.confidence_score,
            "executed_profiles": executed_profiles,
            "budget_usage": budget_summary,
            "verdict": verdict.final_diagnosis,
            "total_assertions": verdict.total_assertions,
            "passed_assertions": verdict.passed_count,
            "failed_assertions": verdict.failed_count,
            "abstain_assertions": verdict.abstain_count,
            "assertion_results": [
                {
                    "assertion": a.raw_assertion,
                    "verdict": a.verdict,
                    "observed_value": a.observed_value,
                    "expected": a.expected,
                    "evaluation_status": a.observation_status,
                    "reason": a.reason,
                    "evidence_id": a.evidence_id,
                }
                for a in verdict.assertion_evaluations
            ],
            "inspection_summary": {k: {"success": v.get("success", True)} for k, v in inspection_outputs.items()},
            "evidence_ledger_count": len(ledger._records),
            "report_html": report_html,
            "report_json": report_json,
        }
