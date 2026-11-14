"""Session persistence: saved only at durable points, each observation stored once, reload gives the same session.

A diagnosis used to rewrite the whole, growing session after every step, and the session text repeated each
observation in up to six places (evidence, record x2, check, methodology copy, conclusion chain, hypotheses).  On a
300-thread target that was ~100 MB per save and most of the diagnosis time.  These tests pin the cheaper format and
the durability semantics that must not change: the completed session is on disk before ``diagnose`` returns, the
reloaded session serializes to the same content and reports the same verdict, and a reload does not overwrite the file
it was loaded from.
"""
import json
import os
import shutil
import subprocess
import sys
import time
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from extractor import expert_diagnostic_engine as ede  # noqa: E402
from extractor.diagnostic_methodology import CheckStatus, DiagnosticCheck  # noqa: E402
from extractor.session_store import (  # noqa: E402
    BLOB_REF, BLOBS_KEY, BlobInterner, encode_document, intern_observations, resolve_blobs)
from tests.support.fixture_process import fixture_popen  # noqa: E402
from tests.support.tmpdirs import temp_dir  # noqa: E402

TARGETS = os.path.join(ROOT, "benchmarks", "diagnosis_accuracy", "targets")


def _plain(session):
    """The session as the plain (pre-blob) serialization produced it."""
    def fb(o):
        if hasattr(o, "to_dict"):
            return o.to_dict()
        if hasattr(o, "value"):
            return o.value
        return str(o)
    return json.loads(json.dumps(session.to_dict(), default=fb))


def _big_observation(n=400):
    return {"threads": [{"tid": 1000 + i, "state": "S", "frames": ["f%d" % j for j in range(8)]} for i in range(n)],
            "thread_count": n}


class TestSessionStoreFormat(unittest.TestCase):
    def test_duplicate_large_value_is_stored_once_and_resolves_back(self):
        big = _big_observation()
        doc = {"a": [{"raw_observation": big}, {"actual_observations": dict(big)}],
               "b": {"details": {"x": big["threads"], "small": 1}}}
        it = BlobInterner()
        text = encode_document(intern_observations(doc, it), it.blobs)
        loaded = json.loads(text)                       # still one plain JSON object
        self.assertEqual(len(loaded[BLOBS_KEY]), 1, "the same thread list must be stored once")
        self.assertLess(len(text), 1.3 * len(json.dumps(big["threads"])))
        self.assertEqual(resolve_blobs(loaded), json.loads(json.dumps(doc)))
        # the live tree is never modified by the interning walk
        self.assertIs(doc["a"][0]["raw_observation"]["threads"], big["threads"])

    def test_small_values_stay_inline_and_legacy_documents_load_unchanged(self):
        doc = {"x": {"raw_observation": {"n": 1, "s": "short"}}}
        it = BlobInterner()
        text = encode_document(intern_observations(doc, it), it.blobs)
        self.assertNotIn(BLOBS_KEY, json.loads(text))
        legacy = {"investigation_id": "i", "checks": [{"actual_observations": {BLOB_REF + "_not": 1}}]}
        self.assertEqual(resolve_blobs(json.loads(json.dumps(legacy))), legacy)

    def test_missing_blob_is_a_corrupt_file(self):
        with self.assertRaises(ValueError):
            resolve_blobs({"k": {BLOB_REF: "deadbeef"}, BLOBS_KEY: {}})


class TestSessionFile(unittest.TestCase):
    def _session_with_shared_observation(self, corpus):
        eng = ede.ExpertDiagnosticEngine(corpus_dir=corpus)
        sess = eng.start_investigation("thread count keeps growing", pid=os.getpid(), investigation_id="INV_PERSIST_COST")
        big = _big_observation()
        for i in range(4):
            ev = {"evidence_id": f"ev_{i}", "recipe_id": f"RECIPE_{i}", "raw_observation": big}
            sess.collected_evidence.append(ev)
            sess.checks.append(DiagnosticCheck(check_id=f"CHK_{i}", recipe_id=f"RECIPE_{i}", status=CheckStatus.PASS,
                                               actual_observations=big))
        return eng, sess, big

    def test_file_stores_the_observation_once_and_reloads_to_the_same_content(self):
        corpus = temp_dir(self, "persist_cost_")
        eng, sess, big = self._session_with_shared_observation(corpus)
        sess._save_to_disk()
        path = os.path.join(corpus, "investigations", "INV_PERSIST_COST.json")
        one = len(json.dumps(big))
        self.assertLess(os.path.getsize(path), 2 * one, "8 copies of the observation must be stored once")
        with open(path, encoding="utf-8") as f:
            self.assertEqual(resolve_blobs(json.load(f)), _plain(sess))
        before = _plain(sess)
        size = os.path.getsize(path)
        fresh = ede.ExpertDiagnosticEngine(corpus_dir=corpus)
        restored = fresh.get_session("INV_PERSIST_COST")
        self.assertEqual(_plain(restored)["checks"], before["checks"])
        self.assertEqual(_plain(restored)["collected_evidence"], before["collected_evidence"])
        # the reload must not have overwritten the file with an empty session
        self.assertEqual(os.path.getsize(path), size)
        again = ede.ExpertDiagnosticEngine(corpus_dir=corpus).get_session("INV_PERSIST_COST")
        self.assertEqual(len(again.checks), 4)

    def test_encoding_failure_is_not_committed_and_leaves_no_temp_file(self):
        corpus = temp_dir(self, "persist_cost_")
        _eng, sess, _big = self._session_with_shared_observation(corpus)
        with mock.patch.object(ede.AdaptiveInvestigationSession, "_persist_text", side_effect=TypeError("boom")):
            with self.assertRaises(ede.InvestigationPersistenceError) as ctx:
                sess._save_to_disk()
        self.assertEqual(ctx.exception.outcome, ede.DurableCommitOutcome.NOT_COMMITTED)
        inv = os.path.join(corpus, "investigations")
        self.assertEqual([f for f in os.listdir(inv) if f.startswith(".tmp_")], [])


@unittest.skipUnless(shutil.which("gcc") and sys.platform.startswith("linux"), "gcc / Linux needed")
class TestDiagnosisSaves(unittest.TestCase):
    def test_diagnosis_saves_at_durable_points_and_the_completed_session_reloads_with_the_same_verdict(self):
        tmp = temp_dir(self, "persist_cost_")
        exe = os.path.join(tmp, "ok_idle_server")
        subprocess.run(["gcc", "-g", "-O0", "-pthread", os.path.join(TARGETS, "ok_idle_server.c"), "-o", exe], check=True)
        p = fixture_popen([exe], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, name="ok_idle_server")
        self.addCleanup(p.kill_tree)
        self.assertEqual(p.stdout.readline().strip(), b"READY")
        time.sleep(0.2)
        saves = []
        real = ede.AdaptiveInvestigationSession._save_to_disk

        def counting(self_):
            saves.append(self_.state)
            return real(self_)
        eng = ede.ExpertDiagnosticEngine(corpus_dir=os.path.join(tmp, "corpus"))
        with mock.patch.object(ede.AdaptiveInvestigationSession, "_save_to_disk", counting):
            res = ede.diagnose(p.pid, exe, "general health check", engine=eng)
        sess = eng.sessions[res.investigation_id]
        self.assertTrue(len(sess.checks) > 5)
        # created, planned, completed: never once per check
        self.assertLessEqual(len(saves), 3, saves)
        self.assertIn(ede.STATE_COLLECTING, saves)
        self.assertIn(saves[-1], ede.TERMINAL_STATES)
        md_before = sess.export_report("markdown")
        verdict_before = sess.export_report("json")["section_a_executive_summary"]["overall_result"]
        eng.sessions.clear()
        restored = eng.get_session(res.investigation_id)
        self.assertEqual(restored.state, sess.state)
        self.assertEqual(restored.export_report("json")["section_a_executive_summary"]["overall_result"], verdict_before)
        self.assertEqual(restored.export_report("markdown"), md_before)


if __name__ == "__main__":
    unittest.main()
