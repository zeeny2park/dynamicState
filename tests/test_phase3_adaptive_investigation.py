"""
Deterministic unit tests for DynamicState Phase 3:
Adaptive Evidence Collection & Diagnosis Efficiency Optimization.
"""

import os
import time
from pathlib import Path
import tempfile
import unittest
from typing import Any, Dict, List, Optional, Tuple

from extractor.diagnostic_recipes import BASELINE_RECIPE_IDS
from extractor.target_adapter import RemoteSshTargetAdapter
from extractor.expert_diagnostic_engine import (
    ExpertDiagnosticEngine,
    AdaptiveInvestigationSession,
    diagnose,
    CheckStatus,
    STATE_COLLECTING,
    STATE_ANALYZING,
    STATE_NARROWING,
    _recipe_snapshot_domains,
)
from extractor.runtime_evidence_provider import RuntimeEvidenceRecord


class MockTrackingRemoteSshAdapter(RemoteSshTargetAdapter):
    """Deterministic mock SSH adapter tracking exact commands and domains."""

    def __init__(self, pid: int = 4242):
        super().__init__(host="10.255.255.1", user="test")
        self.target_pid = pid
        self.executed_commands: List[str] = []
        self.synthetic_stat = (
            f"{pid} (mock_worker) R 1 4242 4242 0 -1 4194304 100 0 0 0 10 20 0 0 20 0 4 0 "
            f"12345678 10485760 1000 18446744073709551615 4194304 5242880 140737488349184 0 0 0 0 0 0 0 0 0 17 0 0 0"
        )
        self.synthetic_status = "Name:\tmock_worker\nVmRSS:\t16384 kB\nVmSize:\t65536 kB\nThreads:\t2\n"
        self.synthetic_maps = (
            "00400000-00452000 r-xp 00000000 08:01 123456 /usr/bin/mock_worker\n"
            "00652000-00653000 r--p 00051000 08:01 123456 /usr/bin/mock_worker\n"
            "00653000-00654000 rw-p 00052000 08:01 123456 /usr/bin/mock_worker\n"
            "01a00000-01a20000 rw-p 00000000 00:00 0 [heap]\n"
            "7f123400-7f123500 r-xp 00000000 08:01 789101 /usr/lib/libc.so.6\n"
        )
        self.synthetic_tasks = (
            f"@@T {pid}\n@@F stat\n{self.synthetic_stat}\n@@F status\nName:\tmock_worker\n"
            f"@@T {pid+1}\n@@F stat\n{pid+1} (mock_sub) S 1 4242 4242 0 -1 0 0 0 0 0 5 5 0 0 20 0 1 0 12345680 0 0 0 0 0 0 0 0 0 0 0 0 0\n"
            f"@@F status\nName:\tmock_sub\n"
        )
        self.synthetic_fds = f"l-wx------ 1 test test 64 /proc/{pid}/fd/0 -> /dev/null\nlrwx------ 1 test test 64 /proc/{pid}/fd/1 -> socket:[9999]\n"

    def run_ssh(self, command: str, timeout: Optional[float] = None) -> Tuple[int, str, str]:
        self.executed_commands.append(command)
        out_parts = []

        if "@@LIVENESS" in command:
            out_parts.extend(["@@LIVENESS", "ALIVE"])
        if "@@COMM" in command:
            out_parts.extend(["@@COMM", "mock_worker"])
        if "@@STAT" in command:
            out_parts.extend(["@@STAT", self.synthetic_stat])
        if "@@STATUS" in command:
            out_parts.extend(["@@STATUS", self.synthetic_status])
        if "@@EXE" in command:
            out_parts.extend(["@@EXE", "/usr/bin/mock_worker"])
        if "@@FP" in command:
            out_parts.extend(["@@FP", "123456:10000:1700000000"])
        if "@@BOOT" in command:
            out_parts.extend(["@@BOOT", "mock-boot-uuid-0001"])
        if "@@OSREL" in command:
            out_parts.extend(["@@OSREL", "6.5.0-generic"])
        if "@@MACH" in command:
            out_parts.extend(["@@MACH", "x86_64"])

        if "@@MAPS" in command:
            out_parts.extend(["@@MAPS", self.synthetic_maps])
        if "@@FDS" in command:
            out_parts.extend(["@@FDS", self.synthetic_fds])
        if "@@TASKS" in command:
            out_parts.extend(["@@TASKS", self.synthetic_tasks])

        out_parts.append("@@END")
        return 0, "\n".join(out_parts), ""


# =============================================================================
# 1. Targeted Collection Tests
# =============================================================================

def test_targeted_snapshot_omits_unneeded_domains():
    adapter = MockTrackingRemoteSshAdapter(pid=5001)

    # 1. Fetch only basic domains
    snap = adapter.prefetch_snapshot(5001, domains={"basic"})
    assert snap is not None
    assert snap["comm"] == "mock_worker"
    assert snap["maps"] is None
    assert snap["threads"] is None
    assert snap["fd_targets"] is None

    # Inspect the exact SSH command
    last_cmd = adapter.executed_commands[-1]
    assert "@@STATUS" in last_cmd
    assert "@@MAPS" not in last_cmd
    assert "@@TASKS" not in last_cmd
    assert "@@FDS" not in last_cmd


def test_targeted_snapshot_merges_subsequent_domains():
    adapter = MockTrackingRemoteSshAdapter(pid=5002)

    # First fetch: basic only
    snap1 = adapter.prefetch_snapshot(5002, domains={"basic"})
    assert snap1 is not None
    assert snap1["maps"] is None

    # Second fetch: maps domain requested within TTL
    snap2 = adapter.prefetch_snapshot(5002, domains={"maps"})
    assert snap2 is not None
    assert snap2["comm"] == "mock_worker"  # preserved from basic
    assert snap2["maps"] is not None       # newly added
    assert snap2["threads"] is None        # still not requested

    # Third query: get_process_status within TTL -> zero new SSH commands!
    cmd_count_before = len(adapter.executed_commands)
    st = adapter.get_process_status(5002)
    assert str(st.get("VmRSS")) == "16384"
    assert len(adapter.executed_commands) == cmd_count_before


def test_recipe_snapshot_domains_helper():
    class DummyRecipe:
        def __init__(self, recipe_id: str, domain: str):
            self.recipe_id = recipe_id
            self.domain = domain

    # FD leak recipe -> requests basic + fds
    fd_rec = DummyRecipe("RECIPE_FD_LEAK_GROWTH", "RESOURCE_LEAK")
    assert _recipe_snapshot_domains(fd_rec) == {"basic", "fds"}

    # Deadlock recipe -> requests basic + threads
    dl_rec = DummyRecipe("RECIPE_POTENTIAL_DEADLOCK_PATTERNS", "CONCURRENCY_DEADLOCK")
    assert _recipe_snapshot_domains(dl_rec) == {"basic", "threads"}

    # Memory growth recipe -> requests basic + maps
    mem_rec = DummyRecipe("RECIPE_PROCESS_MEMORY_GROWTH", "MEMORY_GROWTH")
    assert _recipe_snapshot_domains(mem_rec) == {"basic", "maps"}


# =============================================================================
# 2. Evidence Inventory & Reuse Tests
# =============================================================================

def test_evidence_inventory_reuses_valid_fresh_evidence():
    engine = ExpertDiagnosticEngine()
    adapter = MockTrackingRemoteSshAdapter(pid=5003)
    sess = engine.start_investigation(
        problem_statement="process observation",
        pid=5003,
        adapter=adapter,
    )

    # Simulate an existing fresh record in collected_evidence_records
    rec = RuntimeEvidenceRecord(
        evidence_id="ev_test_001",
        collection_method="RECIPE_FD_EXHAUSTION",
        target_pid=5003,
        observed_value=128,
        raw_observation={"fd_count": 128, "max_fds": 1024},
        collection_status="SUCCESS",
        raw_details={"timestamp": time.time()},
    )
    sess.collected_evidence_records.append(rec)

    class DummyFdRecipe:
        recipe_id = "RECIPE_FD_EXHAUSTION"
        problem_category = "FD_LEAK"
        domain = "FD_RESOURCE"

    obs, recs = sess._inventory_reusable_evidence(DummyFdRecipe())
    assert obs is not None
    assert obs.get("fd_count") == 128
    assert len(recs) == 1
    assert recs[0].evidence_id == "ev_test_001"


def test_evidence_inventory_rejects_stale_evidence():
    engine = ExpertDiagnosticEngine()
    sess = engine.start_investigation(
        problem_statement="process observation",
        pid=5004,
    )

    # Stale record (timestamp 10 seconds ago, beyond 5s TTL)
    rec = RuntimeEvidenceRecord(
        evidence_id="ev_stale_001",
        collection_method="RECIPE_FD_EXHAUSTION",
        target_pid=5004,
        observed_value=128,
        raw_observation={"fd_count": 128},
        collection_status="SUCCESS",
        raw_details={"timestamp": time.time() - 10.0},
    )
    sess.collected_evidence_records.append(rec)

    class DummyFdRecipe:
        recipe_id = "RECIPE_FD_EXHAUSTION"

    obs, recs = sess._inventory_reusable_evidence(DummyFdRecipe())
    assert obs is None
    assert recs == []


# =============================================================================
# 3. Target Identity & PID Reuse Safety Tests
# =============================================================================

def test_pid_reuse_invalidates_snapshot_cache():
    adapter = MockTrackingRemoteSshAdapter(pid=5005)

    # Pin initial process identity
    adapter._pinned_identities[5005] = {
        "pid": 5005,
        "start_time": "12345678",
        "boot_id": "mock-boot-uuid-0001",
        "executable": "/usr/bin/mock_worker",
    }

    # First fetch matches pinned start_time (12345678)
    snap = adapter.prefetch_snapshot(5005, domains={"basic"})
    assert snap is not None

    # Simulate PID recycling: new process spawned with different start_time (99999999)
    adapter.synthetic_stat = adapter.synthetic_stat.replace("12345678", "99999999")

    # Second fetch must detect start_time mismatch, invalidate cache, and return None
    snap2 = adapter.prefetch_snapshot(5005, force=True, domains={"basic"})
    assert snap2 is None
    assert 5005 not in adapter._snapshot_cache


# =============================================================================
# 4. Adaptive Early Stopping & Correctness Tests
# =============================================================================

def test_adaptive_early_stopping_on_confirmed_fault(tmp_path):
    engine = ExpertDiagnosticEngine(corpus_dir=str(tmp_path))
    my_pid = os.getpid()
    sess = engine.start_investigation(
        problem_statement="Memory corruption in worker payload pointer",
        pid=my_pid,
    )
    sess.step()  # classify
    sess.step()  # assess
    sess.step()  # plan

    assert sess.plan is not None
    non_baseline_steps = [s for s in sess.plan.steps if s.recipe_id not in BASELINE_RECIPE_IDS and s.category != "MEMORY_CORRUPTION"]
    assert len(non_baseline_steps) > 0

    # Patch evaluate_recipe so first step confirms fault with confidence 0.95
    def mock_eval(r, ctx):
        from extractor.expert_diagnostic_engine import RecipeEvaluationResult, RECIPE_STATUS_SUPPORTED
        return RecipeEvaluationResult(
            recipe_id=r.recipe_id,
            status=RECIPE_STATUS_SUPPORTED,
            confidence=0.95,
            confidence_basis="Mock confirmed fault",
            supporting_facts=["invalid pointer dereference detected"],
            contradicting_facts=[],
        )
    sess.recipe_registry.evaluate_recipe = mock_eval

    # Advance one step (executes first step, triggers early stop on non-baseline steps)
    sess.step()

    skipped = [s for s in sess.plan.steps if s.status == "SKIPPED" and s.not_run_reason == "early_stop_sufficient_evidence"]
    assert len(skipped) > 0
    for s in skipped:
        assert s.recipe_id not in BASELINE_RECIPE_IDS


def test_missing_evidence_cannot_produce_false_healthy(tmp_path):
    engine = ExpertDiagnosticEngine(corpus_dir=str(tmp_path))
    sess = engine.start_investigation(
        problem_statement="general health check",
        pid=5007,
    )
    sess.step()  # classify
    sess.step()  # assess
    sess.step()  # plan

    # Force assessment limitation
    if sess.target_assessment:
        sess.target_assessment.memory_readable = False
        sess.target_assessment.limitations.append("Memory unreadable")

    # Analyze without running checks
    sess.state = STATE_ANALYZING
    sess._step_analyze()
    sess._step_verify()
    sess._step_narrow()

    # Verdict must be INCONCLUSIVE, NEVER HEALTHY
    assert sess.conclusion is not None
    assert sess.conclusion.stop_reason != "HEALTHY"
    assert "HEALTHY" not in [h.status for h in sess.active_hypotheses if h.category == "HEALTHY"]


def test_contradictory_evidence_preserves_ambiguity(tmp_path):
    engine = ExpertDiagnosticEngine(corpus_dir=str(tmp_path))
    sess = engine.start_investigation(
        problem_statement="memory leak investigation",
        pid=5008,
    )
    sess.step()  # classify
    sess.step()  # assess

    # Inject one supporting and one contradicting evidence for memory growth
    sess.collected_evidence.append({
        "evidence_id": "ev_supp_01",
        "problem_category": "MEMORY_LEAK",
        "status": "SUPPORTED",
        "recipe_id": "RECIPE_PROCESS_MEMORY_GROWTH",
        "details": {"confidence": 0.85, "finding_summary": "Observed rapid RSS growth"},
    })
    sess.collected_evidence.append({
        "evidence_id": "ev_contra_01",
        "problem_category": "MEMORY_LEAK",
        "status": "CONTRADICTED",
        "recipe_id": "RECIPE_HEAP_GROWTH",
        "details": {"confidence": 0.80, "finding_summary": "Heap in-use trend is flat"},
    })

    sess.state = STATE_ANALYZING
    sess._step_analyze()

    # The hypothesis must be marked PROPOSED (ambiguous), not SUPPORTED or HEALTHY
    hyp = next((h for h in sess.active_hypotheses if h.category == "MEMORY_LEAK"), None)
    assert hyp is not None
    assert hyp.status == "PROPOSED"
    assert hyp.confidence == 0.45
    assert len(hyp.supporting_evidence) == 1
    assert len(hyp.contradicting_evidence) == 1
    assert "Ambiguous" in hyp.confidence_basis


def test_partial_snapshot_failure_isolation():
    # If /proc/PID/fd fails with permission denied, status and maps are still returned
    adapter = MockTrackingRemoteSshAdapter(pid=5009)
    # Simulate /proc/PID/fd permission denial
    adapter.synthetic_fds = "ls: cannot open directory '/proc/5009/fd': Permission denied\n"

    snap = adapter.prefetch_snapshot(5009, domains={"basic", "maps", "fds"})
    assert snap is not None
    assert snap["comm"] == "mock_worker"
    assert snap["maps"] is not None
    assert snap["fd_count"] == 0  # isolated, does not crash or corrupt maps/status



class TestPhase3AdaptiveUnittest(unittest.TestCase):
    def test_targeted_snapshot_omits_unneeded_domains(self):
        test_targeted_snapshot_omits_unneeded_domains()

    def test_targeted_snapshot_merges_subsequent_domains(self):
        test_targeted_snapshot_merges_subsequent_domains()

    def test_recipe_snapshot_domains_helper(self):
        test_recipe_snapshot_domains_helper()

    def test_evidence_inventory_reuses_valid_fresh_evidence(self):
        test_evidence_inventory_reuses_valid_fresh_evidence()

    def test_evidence_inventory_rejects_stale_evidence(self):
        test_evidence_inventory_rejects_stale_evidence()

    def test_pid_reuse_invalidates_snapshot_cache(self):
        test_pid_reuse_invalidates_snapshot_cache()

    def test_adaptive_early_stopping_on_confirmed_fault(self):
        with tempfile.TemporaryDirectory() as td:
            test_adaptive_early_stopping_on_confirmed_fault(Path(td))

    def test_missing_evidence_cannot_produce_false_healthy(self):
        with tempfile.TemporaryDirectory() as td:
            test_missing_evidence_cannot_produce_false_healthy(Path(td))

    def test_contradictory_evidence_preserves_ambiguity(self):
        with tempfile.TemporaryDirectory() as td:
            test_contradictory_evidence_preserves_ambiguity(Path(td))

    def test_partial_snapshot_failure_isolation(self):
        test_partial_snapshot_failure_isolation()
