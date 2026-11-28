import os
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from extractor.capture_backend import set_default_trust_store
from extractor.diagnostic_report import CheckStatus
from extractor.expert_diagnostic_engine import ExpertDiagnosticEngine
from extractor.runtime_evidence_provider import (
    COLLECTION_STATUS_FAILED,
    OBSERVATION_COLLECTORS,
    RuntimeEvidenceProvider,
)
from extractor.target_adapter import RemoteSshTargetAdapter
from extractor.thread_sampler import ThreadSampler, ThreadSamplingConfig
from tests.support.fixture_process import fixture_popen


class TestRemoteCollectionBoundsAndIsolation(unittest.TestCase):
    def setUp(self):
        set_default_trust_store(None)
        self.tmpdir = tempfile.mkdtemp(dir=os.environ.get("TMPDIR", "/tmp"))
        self.src_path = os.path.join(self.tmpdir, "bound_target.c")
        self.bin_path = os.path.join(self.tmpdir, "bound_target")
        with open(self.src_path, "w", encoding="utf-8") as f:
            f.write(
                """
                #include <sys/prctl.h>
                #include <unistd.h>
                int main(void) {
                #ifdef PR_SET_PTRACER
                    prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);
                #endif
                    while (1) {
                        usleep(100000);
                    }
                    return 0;
                }
                """
            )
        subprocess.run(["gcc", "-g", "-O0", self.src_path, "-o", self.bin_path], check=True)
        self.proc = fixture_popen([self.bin_path])
        time.sleep(0.05)

    def tearDown(self):
        set_default_trust_store(None)
        if self.proc and self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait(timeout=2)

    def test_remote_adapter_collection_deadline_cuts_slow_ssh(self):
        """A hung/slow SSH command is bounded by collection_deadline instead of waiting full timeout_sec."""
        def slow_runner(cmd_args, timeout, input_bytes=None):
            time.sleep(min(timeout, 5.0))
            return -1, "", f"SSH command timed out after {timeout:.1f}s"

        ad = RemoteSshTargetAdapter(
            host="127.0.0.1",
            timeout_sec=10.0,
            use_daemon=False,
            command_runner=slow_runner,
        )
        t0 = time.monotonic()
        with ad.collection_deadline(0.4):
            rc, _out, err = ad.run_ssh("sleep 10")
        elapsed = time.monotonic() - t0
        self.assertEqual(rc, -1)
        self.assertLess(elapsed, 1.5)
        self.assertIn("timed out", err.lower())

        # Once deadline is already expired, subsequent calls fail instantaneously (0 wait)
        with ad.collection_deadline(0.01):
            time.sleep(0.02)
            t1 = time.monotonic()
            rc2, _out2, err2 = ad.run_ssh("echo hi")
            self.assertEqual(rc2, -1)
            self.assertIn("deadline exceeded", err2.lower())
            self.assertLess(time.monotonic() - t1, 0.1)

    def test_ssh_args_include_server_alive_keepalive(self):
        """SSH arguments include ServerAliveInterval and ServerAliveCountMax to prevent TCP hang."""
        ad = RemoteSshTargetAdapter(host="127.0.0.1", use_daemon=False)
        args = ad._ssh_args("true")
        joined = " ".join(args)
        self.assertIn("ServerAliveInterval=2", joined)
        self.assertIn("ServerAliveCountMax=2", joined)

    def test_single_recipe_exception_does_not_abort_other_diagnoses(self):
        """When one recipe raises TimeoutError or RuntimeError during collection, remaining recipes still run."""
        engine = ExpertDiagnosticEngine(corpus_dir=self.tmpdir)
        session = engine.start_investigation(
            problem_statement="general health check",
            pid=self.proc.pid,
            companion_elf=self.bin_path,
        )

        orig_collect = session.evidence_provider.collect_for_recipe
        failed_once = {"recipe_id": None}

        def flaky_collect(recipe, *args, **kwargs):
            rid = getattr(recipe, "recipe_id", str(recipe))
            if failed_once["recipe_id"] is None:
                failed_once["recipe_id"] = rid
                raise TimeoutError(f"Simulated remote hang in {rid}")
            return orig_collect(recipe, *args, **kwargs)

        session.evidence_provider.collect_for_recipe = flaky_collect
        conclusion = session.run_to_completion()
        self.assertIsNotNone(conclusion)

        error_checks = [c for c in session.checks if c.status == CheckStatus.ERROR]
        non_error_checks = [c for c in session.checks if c.status in (CheckStatus.PASS, CheckStatus.FAIL, CheckStatus.INCONCLUSIVE)]
        self.assertEqual(len(error_checks), 1)
        self.assertEqual(error_checks[0].recipe_id, failed_once["recipe_id"])
        self.assertGreaterEqual(len(non_error_checks), 2, "Remaining recipes must still execute after one fails")

    def test_observation_collector_exception_is_isolated(self):
        """An exception inside a single observation collector records failure without crashing collect_for_recipe."""
        provider = RuntimeEvidenceProvider()
        class DummyRecipe:
            recipe_id = "RECIPE_DUMMY_TEST"
            domain = "TEST"
            observations = ("dummy_failing_obs",)

        def boom_collector(_prov, _ctx):
            raise RuntimeError("remote pipe broken")

        with patch.dict(OBSERVATION_COLLECTORS, {"dummy_failing_obs": boom_collector}):
            obs_data, recs = provider.collect_for_recipe(DummyRecipe(), self.proc.pid, self.bin_path)
        self.assertTrue(any("dummy_failing_obs" in e for e in obs_data.get("collection_errors", [])))
        self.assertTrue(any(r.collection_status == COLLECTION_STATUS_FAILED for r in recs))

    def test_thread_sampler_exits_cleanly_on_repeated_enum_exceptions_or_deadline(self):
        """ThreadSampler breaks out of loop on repeated remote errors or expired deadline."""
        class FailingRemoteAdapter(RemoteSshTargetAdapter):
            thread_samples_supported = True
            def check_liveness(self, pid):
                return True, None
            def read_thread_samples(self, pid, prev_counters=None):
                raise TimeoutError("remote daemon timeout")

        ad = FailingRemoteAdapter(host="127.0.0.1", use_daemon=False)
        sampler = ThreadSampler(ad, watch_manager=None, budget_tracker=None)
        t0 = time.monotonic()
        series = sampler.collect(
            self.proc.pid,
            self.bin_path,
            ThreadSamplingConfig(samples=5, interval_sec=0.5),
        )
        self.assertLess(time.monotonic() - t0, 1.5)
        self.assertIn("failed repeatedly", series.stop_reason or "")


if __name__ == "__main__":
    unittest.main()
