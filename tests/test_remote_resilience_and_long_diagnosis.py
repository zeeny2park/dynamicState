"""Tests for remote diagnosis resilience, exception isolation, and long-running timeout handling."""

import os
import shutil
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from extractor.diagnostic_methodology import CheckStatus
from extractor.diagnostic_recipes import DiagnosticRecipeRegistry
from extractor.expert_diagnostic_engine import (
    AdaptiveInvestigationSession,
    ExpertDiagnosticEngine,
    InvestigationPlan,
    InvestigationStep,
    MAX_CONSECUTIVE_REMOTE_FAILURES,
    STATE_COLLECTING,
    STATE_INCONCLUSIVE,
    TERMINAL_STATES,
)
from extractor.observation_budget import ObservationBudgetLimits, ObservationBudgetTracker
from extractor.target_adapter import RemoteSshTargetAdapter
from extractor.web.diagnose_jobs import DiagnoseJob, DiagnoseJobManager, outcome_notice


class TestRemoteTransportResilience(unittest.TestCase):
    """RemoteSshTargetAdapter stale ControlMaster recovery and bounded ConnectTimeout."""

    def test_stale_control_master_triggers_single_clean_retry(self):
        calls = []

        def fake_runner(args, timeout, **kwargs):
            calls.append((list(args), timeout))
            if len(calls) == 1:
                return 255, "", "mux_client_request_session: session request failed: Broken pipe"
            return 0, "ok\n", ""

        ad = RemoteSshTargetAdapter(
            host="10.0.0.5",
            user="ops",
            command_runner=fake_runner,
            use_control_master=True,
            timeout_sec=5.0,
        )
        rc, out, err = ad.run_ssh("echo ok")
        self.assertEqual(rc, 0)
        self.assertEqual(out.strip(), "ok")
        self.assertEqual(len(calls), 2)
        # First call used ControlMaster, second call retried without ControlMaster
        self.assertTrue(any("ControlMaster=auto" in a for a in calls[0][0]))
        self.assertFalse(any("ControlMaster=auto" in a for a in calls[1][0]))

    def test_connect_timeout_bounded_by_remaining_deadline(self):
        captured = []

        def fake_runner(args, timeout, **kwargs):
            captured.append((list(args), timeout))
            return 0, "ok\n", ""

        ad = RemoteSshTargetAdapter(
            host="10.0.0.5",
            command_runner=fake_runner,
            use_control_master=False,
            timeout_sec=10.0,
        )
        with ad.collection_deadline(1.2):
            rc, _, _ = ad.run_ssh("true")
        self.assertEqual(rc, 0)
        self.assertEqual(len(captured), 1)
        args, _t = captured[0]
        self.assertIn("ConnectTimeout=2", args)


class TestRemoteCircuitBreakerAndRecipeIsolation(unittest.TestCase):
    """Circuit breaker on consecutive remote transport errors & per-step evaluate_recipe isolation."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="test_remote_resil_")
        self.engine = ExpertDiagnosticEngine(corpus_dir=self.tmpdir)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _make_remote_session(self, recipe_ids):
        ad = RemoteSshTargetAdapter(
            host="10.0.0.9",
            command_runner=lambda args, timeout, **kw: (0, "", ""),
            use_control_master=False,
        )
        sess = AdaptiveInvestigationSession(
            investigation_id="INV_REMOTE_RESIL",
            problem_statement="general health check",
            pid=os.getpid(),
            adapter=ad,
            corpus_dir=self.tmpdir,
        )
        steps = []
        for idx, rid in enumerate(recipe_ids, 1):
            r = sess.recipe_registry.get_recipe(rid)
            steps.append(InvestigationStep(
                step_id=f"step_{idx:02d}",
                recipe_id=rid,
                recipe_name=r.name if r else rid,
                category=r.problem_category if r else "UNKNOWN",
                domain=r.domain if r else "general",
                rationale="test",
                priority=idx,
                cost_score=0.5,
                safety_score=1.0,
                expected_info_gain=0.5,
                multi_factor_score=0.5,
            ))
        sess.plan = InvestigationPlan(steps=steps, total_steps=len(steps), current_step_index=0)
        sess.state = STATE_COLLECTING
        return sess

    def test_consecutive_remote_transport_failures_trigger_circuit_breaker(self):
        rids = [r.recipe_id for r in DiagnosticRecipeRegistry().list_recipes()[:6]]
        self.assertGreaterEqual(len(rids), MAX_CONSECUTIVE_REMOTE_FAILURES + 2)
        sess = self._make_remote_session(rids)

        call_count = {"n": 0}
        def failing_collect(**kwargs):
            call_count["n"] += 1
            raise TimeoutError("SSH command timed out after 5.0s")

        sess.evidence_provider.collect_for_recipe = failing_collect
        sess.adapter.begin_capture_transaction = MagicMock(side_effect=TimeoutError("SSH command timed out"))
        conclusion = sess.run_to_completion()

        # Must stop after MAX_CONSECUTIVE_REMOTE_FAILURES instead of trying all 6 steps!
        self.assertEqual(conclusion.stop_reason, "REMOTE_CONNECTION_LOST")
        self.assertEqual(sess.state, STATE_INCONCLUSIVE)
        skipped_lost = [s for s in sess.plan.steps if s.not_run_reason == "remote_connection_lost"]
        self.assertEqual(len(skipped_lost), len(rids) - MAX_CONSECUTIVE_REMOTE_FAILURES)

    def test_evaluate_recipe_exception_is_isolated_to_failing_step(self):
        rids = [r.recipe_id for r in DiagnosticRecipeRegistry().list_recipes()[:2]]
        sess = self._make_remote_session(rids)

        sess.adapter.begin_capture_transaction = MagicMock(return_value=None)
        sess.evidence_provider.collect_for_recipe = MagicMock(return_value=({"observed_value": 1}, []))

        orig_eval = sess.recipe_registry.evaluate_recipe
        calls = {"n": 0}
        def flaky_eval(recipe, ctx):
            calls["n"] += 1
            if calls["n"] == 1:
                raise ZeroDivisionError("simulated partial remote data division by zero")
            return orig_eval(recipe, ctx)

        sess.recipe_registry.evaluate_recipe = flaky_eval
        res1 = sess._step_collect_next()
        self.assertEqual(res1["action"], "COLLECT_STEP_FAILED")
        self.assertEqual(sess.checks[0].status, CheckStatus.ERROR)
        self.assertIn("Recipe evaluation failed", sess.checks[0].error_details)

        # Second step still runs cleanly!
        res2 = sess._step_collect_next()
        self.assertNotEqual(res2.get("action"), "COLLECT_STEP_FAILED")
        self.assertEqual(len(sess.checks), 2)

    def test_run_to_completion_halts_immediately_when_budget_exhausted(self):
        rids = [r.recipe_id for r in DiagnosticRecipeRegistry().list_recipes()[:3]]
        sess = self._make_remote_session(rids)
        sess.budget_tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_wall_clock_ms=1.0))
        sess.budget_tracker.metrics.is_budget_exhausted = True
        sess.budget_tracker.metrics.exhaustion_reason = "Wall-clock budget exceeded"
        with patch.object(sess.budget_tracker, "can_continue", return_value=False):
            conclusion = sess.run_to_completion()
        self.assertEqual(conclusion.stop_reason, "BUDGET_EXHAUSTED")
        self.assertIn(sess.state, TERMINAL_STATES)


class TestWebDiagnoseJobCancellationAndNotices(unittest.TestCase):
    """Web UI DiagnoseJobManager cancellation and remote outcome notices."""

    def test_outcome_notice_surfaces_remote_failures_and_budget_exhaustion(self):
        job = DiagnoseJob({"pid": 1234, "remote_target": {"remote_host": "10.0.0.5"}})

        n1 = outcome_notice({"not_covered": [{"kind": "target_unreachable", "reason": "ssh timeout"}]}, job)
        self.assertEqual(n1["code"], "TARGET_UNREACHABLE")

        n2 = outcome_notice({"not_covered": [{"kind": "remote_connection_lost", "reason": "3 timeouts"}]}, job)
        self.assertEqual(n2["code"], "REMOTE_CONNECTION_LOST")

        n3 = outcome_notice({"not_covered": [{"kind": "stage_failed", "reason": "RuntimeError: boom"}]}, job)
        self.assertEqual(n3["code"], "DIAGNOSE_PARTIAL_ERROR")

        n4 = outcome_notice({"stop_reason": "BUDGET_EXHAUSTED", "summary": "time limit reached"}, job)
        self.assertEqual(n4["code"], "TIME_BUDGET_EXCEEDED")

    def test_cancel_pauses_session_and_emits_event(self):
        mgr = DiagnoseJobManager(engine_getter=lambda: None, serialize=lambda x: x)
        job = DiagnoseJob({"pid": 1234, "remote_target": {"remote_host": "10.0.0.5"}})
        fake_sess = MagicMock()
        fake_sess.is_paused = False
        job.session = fake_sess
        mgr._jobs[job.job_id] = job

        res = mgr.cancel(job.job_id)
        self.assertTrue(res["success"])
        self.assertTrue(res["cancelled"])
        self.assertTrue(fake_sess.is_paused)
        self.assertTrue(any(e["type"] == "cancel_requested" for e in job.events))


if __name__ == "__main__":
    unittest.main()
