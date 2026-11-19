import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest

from extractor.agent_runtime import AgentRuntime
from extractor.check_budget import DefaultCheckBudget
from extractor.expert_diagnostic_engine import (
    ExpertDiagnosticEngine,
    diagnose,
)
from extractor.recipe_plugins.mapping_growth import _proc_sample, _thread_counts
from extractor.web.server import WebApiAdapter


class TestContinueCollectedDiagnosis(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(dir=os.environ.get("TMPDIR", "/tmp"))
        self.src_path = os.path.join(self.tmpdir, "sleep_target.c")
        self.bin_path = os.path.join(self.tmpdir, "sleep_target")
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
        self.proc = subprocess.Popen([self.bin_path])
        time.sleep(0.05)

    def tearDown(self):
        if self.proc and self.proc.poll() is None:
            try:
                os.kill(self.proc.pid, signal.SIGKILL)
                self.proc.wait(timeout=2)
            except Exception:
                pass

    def test_step_budget_reached_synthesizes_collected_evidence(self):
        """Even if max_steps stops the loop early, collected evidence is synthesized."""
        engine = ExpertDiagnosticEngine(corpus_dir=self.tmpdir)
        session = engine.start_investigation(
            problem_statement="check process status",
            pid=self.proc.pid,
            companion_elf=self.bin_path,
        )
        conclusion = session.run_to_completion(max_steps=4)
        self.assertIsNotNone(conclusion)
        self.assertEqual(conclusion.stop_reason, "STEP_BUDGET_REACHED")
        self.assertTrue(len(session.collected_evidence) >= 1)
        self.assertTrue(len(session.active_hypotheses) >= 1)

    def test_continue_collected_only_runs_offline_after_target_exits(self):
        """Pre-collected/co-sampled data can be diagnosed even after the target process terminates."""
        inv_dir = os.path.join(self.tmpdir, "inv_store")
        engine = ExpertDiagnosticEngine(corpus_dir=inv_dir)

        session = engine.start_investigation(
            problem_statement="general health check",
            pid=self.proc.pid,
            companion_elf=self.bin_path,
            default_check_budget=DefaultCheckBudget.resolve(0.1, 0.05),
        )
        pid_str = str(self.proc.pid)
        ms = _proc_sample(session.adapter, self.proc.pid)
        tc = {str(k): v for k, v in _thread_counts(session.adapter, self.proc.pid).items()}
        session.evidence_provider.import_precollected_state({
            "fd_cosamples": {
                pid_str: [
                    [1.0, {str(i): "pipe:[100]" for i in range(10)}, 1],
                    [1.2, {str(i): "pipe:[100]" for i in range(15)}, 1],
                    [1.4, {str(i): "pipe:[100]" for i in range(20)}, 1],
                    [1.6, {str(i): "pipe:[100]" for i in range(25)}, 1],
                ]
            },
            "mapping_cosamples": {
                pid_str: [[dict(ms, t=1.0 + i * 0.2), tc] for i in range(4)]
            },
        })
        session.run_to_completion(max_steps=3)
        inv_id = session.investigation_id

        os.kill(self.proc.pid, signal.SIGKILL)
        self.proc.wait(timeout=2)

        engine2 = ExpertDiagnosticEngine(corpus_dir=inv_dir)
        resumed = engine2.continue_investigation(
            inv_id,
            collected_only=True,
        )
        executed_recipes = {c.recipe_id for c in resumed.checks}
        self.assertIn("RECIPE_FD_LEAK", executed_recipes)
        self.assertIn("RECIPE_MAPPING_GROWTH", executed_recipes)
        self.assertIsNotNone(resumed.conclusion)

    def test_diagnose_resume_live_completes_skipped_checks(self):
        """Resuming via diagnose(..., resume_investigation_id=...) expands budget and finishes skipped checks."""
        res1 = diagnose(
            self.proc.pid,
            self.bin_path,
            corpus_dir=self.tmpdir,
            default_check_budget_s=1.0,
            default_check_max_s=0.5,
        )
        inv_id = res1.investigation_id
        self.assertIsNotNone(inv_id)
        not_run_1 = {
            item["item"]
            for item in res1.not_covered
            if item.get("kind") == "baseline_check_not_run"
        }
        self.assertIn("RECIPE_FD_LEAK", not_run_1)

        res2 = diagnose(
            self.proc.pid,
            self.bin_path,
            corpus_dir=self.tmpdir,
            resume_investigation_id=inv_id,
            continue_collected_only=False,
        )
        self.assertEqual(res2.investigation_id, inv_id)
        not_run_2 = {
            item["item"]
            for item in res2.not_covered
            if item.get("kind") == "baseline_check_not_run"
        }
        self.assertNotIn("RECIPE_FD_LEAK", not_run_2)
        self.assertNotIn("RECIPE_MAPPING_GROWTH", not_run_2)

    def test_cli_diagnose_resume_and_collected_only(self):
        """CLI --resume and --continue-collected-only flags execute and return valid JSON."""
        corpus = os.path.join(self.tmpdir, "cli_corpus")
        cmd1 = [
            sys.executable, "-m", "extractor", "diagnose",
            "-p", str(self.proc.pid),
            "-d", self.bin_path,
            "--corpus", corpus,
            "--default-check-budget", "1.0",
            "--default-check-max", "0.5",
            "--json",
        ]
        p1 = subprocess.run(cmd1, capture_output=True, text=True, check=True)
        d1 = json.loads(p1.stdout)
        inv_id = d1["investigation_id"]
        self.assertTrue(inv_id)

        # Resume live via CLI --resume
        cmd2 = [
            sys.executable, "-m", "extractor", "diagnose",
            "-p", str(self.proc.pid),
            "-d", self.bin_path,
            "--corpus", corpus,
            "--resume", inv_id,
            "--json",
        ]
        p2 = subprocess.run(cmd2, capture_output=True, text=True, check=True)
        d2 = json.loads(p2.stdout)
        self.assertEqual(d2["investigation_id"], inv_id)
        not_run_2 = {x["item"] for x in d2.get("not_covered", []) if x.get("kind") == "baseline_check_not_run"}
        self.assertNotIn("RECIPE_FD_LEAK", not_run_2)

        # Kill target and run --resume + --continue-collected-only
        os.kill(self.proc.pid, signal.SIGKILL)
        self.proc.wait(timeout=2)
        cmd3 = [
            sys.executable, "-m", "extractor", "diagnose",
            "-p", str(self.proc.pid),
            "-d", self.bin_path,
            "--corpus", corpus,
            "--resume", inv_id,
            "--continue-collected-only",
            "--json",
        ]
        p3 = subprocess.run(cmd3, capture_output=True, text=True, check=True)
        d3 = json.loads(p3.stdout)
        self.assertEqual(d3["investigation_id"], inv_id)

    def test_web_api_parse_and_diagnose_resume(self):
        """Web WebApiAdapter parses and executes resume_investigation_id & continue_collected_only."""
        corpus = os.path.join(self.tmpdir, "web_corpus")
        adapter = WebApiAdapter(AgentRuntime(corpus_dir=corpus))
        parsed = adapter._parse_diagnose_request({
            "pid": self.proc.pid,
            "debug_image": self.bin_path,
            "resume_investigation_id": "inv_abc123",
            "continue_collected_only": True,
        })
        self.assertTrue(parsed["success"])
        self.assertEqual(parsed["args"]["resume_investigation_id"], "inv_abc123")
        self.assertTrue(parsed["args"]["continue_collected_only"])

        r1 = adapter.diagnose_api({
            "pid": self.proc.pid,
            "debug_image": self.bin_path,
            "default_check_budget_s": 1.0,
            "default_check_max_s": 0.5,
        })
        self.assertTrue(r1["success"])
        inv_id = r1["result"]["investigation_id"]

        r2 = adapter.diagnose_api({
            "pid": self.proc.pid,
            "debug_image": self.bin_path,
            "resume_investigation_id": inv_id,
            "continue_collected_only": False,
        })
        self.assertTrue(r2["success"])
        self.assertEqual(r2["result"]["investigation_id"], inv_id)


if __name__ == "__main__":
    unittest.main()
