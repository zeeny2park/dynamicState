"""DEF-ARM-1: a deadlock check that could not decode mutex owners must not report "no deadlock".

A REAL deadlocked process is diagnosed through the expert engine and ``diagnose()`` while the owner-support gate is
patched to NOT_SUPPORTED_ON_TARGET (and, separately, while ABI detection fails).  The deadlock recipe must be neither
CONTRADICTED nor a passed check, the verdict INCONCLUSIVE, ``not_covered`` must name the reason, no owner TID is
reported and the human summary (en, ko) must say the check could not be done.
"""

import os
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest import mock

from extractor import watch_session as ws
from extractor.inspection import threads as ws_threads  # the lock-owner decision lives here (moved from watch_session)
from extractor.diagnostic_recipes import (
    RECIPE_POTENTIAL_DEADLOCK_PATTERNS, RECIPE_STATUS_CONTRADICTED, RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
    DiagnosticRecipeRegistry,
)
from extractor.expert_diagnostic_engine import CheckStatus, ExpertDiagnosticEngine, diagnose
from extractor.human_report import render_human_report
from extractor.runtime_evidence_provider import RuntimeEvidenceProvider
from extractor.target_abi import (
    FEATURE_MUTEX_OWNER, SUPPORT_INCONCLUSIVE, SUPPORT_NOT_SUPPORTED_ON_TARGET, SupportDecision,
)

FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "real_runtime",
                       "proc_thread_circular_deadlock.c")
_real_check_support = ws.check_support


def _patched(status):
    def fake(abi, feature):
        if feature == FEATURE_MUTEX_OWNER:
            return SupportDecision(feature, status, "not supported on this target (patched for test)")
        return _real_check_support(abi, feature)
    return fake


@unittest.skipUnless(shutil.which("gcc"), "gcc not available")
class TestLockOwnerUnsupportedIsNotNoDeadlock(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="defarm1_")
        cls.addClassCleanup(shutil.rmtree, cls.tmp, True)
        cls.exe = os.path.join(cls.tmp, "dl")
        subprocess.run(["gcc", "-g", "-O0", "-Wl,--build-id=sha1", FIXTURE, "-o", cls.exe, "-pthread"], check=True)

    def _launch(self):
        proc = subprocess.Popen([self.exe], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)

        def _kill():
            try:
                proc.kill()
            except OSError:
                pass
            proc.wait()
        self.addCleanup(_kill)
        time.sleep(0.5)
        self.assertIsNone(proc.poll())
        return proc

    def _engine_path(self, pid):
        session = ExpertDiagnosticEngine().start_investigation(
            problem_statement="the process hangs, threads are stuck", pid=pid, companion_elf=self.exe)
        session.run_to_completion(max_steps=30)
        return session

    def _assert_not_evaluated(self, status):
        proc = self._launch()
        with mock.patch.object(ws_threads, "check_support", _patched(status)):
            # provider -> recipe, directly
            recipe = DiagnosticRecipeRegistry.get_recipe(RECIPE_POTENTIAL_DEADLOCK_PATTERNS)
            obs, _ = RuntimeEvidenceProvider().collect_for_recipe(recipe, proc.pid, self.exe, session_id="d1", epoch_id=1)
            self.assertEqual(obs.get("lock_owner_status"), status)
            self.assertFalse(obs.get("deadlock_detected"))
            for lk in obs["callstacks_info"].get("locks", []):
                self.assertFalse(lk.get("owner_tid"))
            res = DiagnosticRecipeRegistry.evaluate_recipe(RECIPE_POTENTIAL_DEADLOCK_PATTERNS, obs)
            self.assertEqual(res.status, RECIPE_STATUS_INSUFFICIENT_EVIDENCE, res.confidence_basis)
            self.assertIn("not supported on this target", res.confidence_basis)

            # engine path
            session = self._engine_path(proc.pid)
            dl = [c for c in session.checks if c.recipe_id == RECIPE_POTENTIAL_DEADLOCK_PATTERNS]
            self.assertTrue(dl, "deadlock recipe did not run")
            for c in dl:
                self.assertNotIn(c.status, (CheckStatus.PASS, CheckStatus.FAIL))
                self.assertEqual(c.status, CheckStatus.INCONCLUSIVE)

            # diagnose()
            out = diagnose(proc.pid, debug_image=self.exe, include_report=True)
        self.assertEqual(out.verdict, "INCONCLUSIVE")
        self.assertEqual(out.findings, [])
        dl_rows = [r for r in out.checks_run if r["recipe_id"] == RECIPE_POTENTIAL_DEADLOCK_PATTERNS]
        self.assertTrue(dl_rows)
        self.assertTrue(all(r["status"] != CheckStatus.PASS for r in dl_rows))
        nc = [n for n in out.not_covered if n["kind"] == "unsupported_on_target"
              and (n["item"] == RECIPE_POTENTIAL_DEADLOCK_PATTERNS or n["item"] == "lock_owner_decoding")]
        self.assertTrue(nc, out.not_covered)
        self.assertTrue(any("not supported on this target" in n["reason"] for n in nc))
        d = out.to_dict()
        for lang, needle in (("en", "Not supported on this target"), ("ko", "지원되지 않아 확인하지 않았습니다")):
            text = render_human_report(d, d.get("report"), lang=lang)
            line = [l for l in text.splitlines() if needle in l]
            self.assertTrue(line, text)
            self.assertIn(RECIPE_POTENTIAL_DEADLOCK_PATTERNS, line[0])
            self.assertNotIn("no deadlock", text.lower())

    def test_owner_decoding_unsupported(self):
        self._assert_not_evaluated(SUPPORT_NOT_SUPPORTED_ON_TARGET)

    def test_abi_detection_failure(self):
        self._assert_not_evaluated(SUPPORT_INCONCLUSIVE)


if __name__ == "__main__":
    unittest.main()
