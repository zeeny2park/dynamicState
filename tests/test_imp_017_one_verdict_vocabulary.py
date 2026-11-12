"""IMP-017: one user-visible verdict vocabulary (the aggregator's) and the explicit mappings at its boundary.

Every interface that shows a process verdict - diagnose(), the incident report export, the auto-triage scan, the
symptom investigator and the staged (snapshot) investigation report - must show one of
``diagnostic_verdict_aggregator.ALL_OVERALL_VERDICTS``.  Older labels reach it only through the mappings tested
here.
"""

import os
import subprocess
import tempfile
import time
import unittest

from extractor.diagnostic_verdict_aggregator import (
    ALL_OVERALL_VERDICTS,
    FINAL_DIAGNOSIS_TO_VERDICT,
    VERDICT_CONFIRMED_FAULT,
    VERDICT_HEALTHY,
    VERDICT_INCONCLUSIVE,
    VERDICT_PROBABLE_FAULT,
    health_score_for,
    to_overall_verdict,
    verdict_for_scan,
)
from extractor.verdict_engine import HYPOTHESIS_OUTCOME_TO_DIAGNOSIS, VALID_FINAL_DIAGNOSES
from extractor.incident_report import export_incident_report
from extractor.watch_session import WatchSessionManager


class TestBoundaryMappings(unittest.TestCase):
    def test_every_final_diagnosis_label_maps_into_the_one_vocabulary(self):
        self.assertEqual(set(FINAL_DIAGNOSIS_TO_VERDICT), set(VALID_FINAL_DIAGNOSES))
        for label in VALID_FINAL_DIAGNOSES:
            self.assertIn(to_overall_verdict(label), ALL_OVERALL_VERDICTS)
        # "no issue within scope" / "refuted" carry no required-check coverage: never HEALTHY
        for label in ("NO_ISSUE_DETECTED", "NO_ISSUE_DETECTED_WITHIN_SCOPE", "REFUTED", "INCONCLUSIVE"):
            self.assertEqual(to_overall_verdict(label), VERDICT_INCONCLUSIVE)
        self.assertEqual(to_overall_verdict("CONFIRMED"), VERDICT_CONFIRMED_FAULT)
        self.assertEqual(to_overall_verdict("SUSPECTED"), VERDICT_PROBABLE_FAULT)
        for v in ALL_OVERALL_VERDICTS:
            self.assertEqual(to_overall_verdict(v), v)
        self.assertEqual(to_overall_verdict("WARNINGS_FOUND"), VERDICT_INCONCLUSIVE)
        self.assertEqual(to_overall_verdict(None), VERDICT_INCONCLUSIVE)

    def test_hypothesis_outcomes_map_onto_final_diagnosis_labels(self):
        self.assertEqual(set(HYPOTHESIS_OUTCOME_TO_DIAGNOSIS), {"CONFIRMED", "PARTIALLY_CONFIRMED", "REFUTED", "ABSTAIN"})
        for label in HYPOTHESIS_OUTCOME_TO_DIAGNOSIS.values():
            self.assertIn(label, VALID_FINAL_DIAGNOSES)

    def test_scan_verdict_never_healthy(self):
        self.assertEqual(verdict_for_scan([]), VERDICT_INCONCLUSIVE)
        self.assertEqual(verdict_for_scan(None), VERDICT_INCONCLUSIVE)
        self.assertEqual(verdict_for_scan([{"severity": "CRITICAL"}]), VERDICT_PROBABLE_FAULT)

    def test_health_score_is_derived_from_the_verdict(self):
        self.assertIsNone(health_score_for(VERDICT_INCONCLUSIVE, []))
        self.assertIsNone(health_score_for("ABORTED", [{"severity": "HIGH"}]))
        self.assertEqual(health_score_for(VERDICT_HEALTHY, []), 100)
        self.assertEqual(health_score_for(VERDICT_PROBABLE_FAULT, [{"severity": "CRITICAL"}, {"severity": "HIGH"}]), 55)
        self.assertEqual(health_score_for(VERDICT_PROBABLE_FAULT, []), 90)  # a fault never reads as a clean 100
        self.assertEqual(health_score_for(VERDICT_CONFIRMED_FAULT, [{"severity": "CRITICAL"}] * 5), 0)


class TestInterfacesUseTheOneVocabulary(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="imp017_vocab_")
        cls.proc = subprocess.Popen(["sleep", "60"])
        time.sleep(0.2)

    @classmethod
    def tearDownClass(cls):
        cls.proc.kill()
        cls.proc.wait(timeout=5)
        cls.tmp.cleanup()

    def test_export_of_a_nonexistent_process_is_inconclusive(self):
        rep = export_incident_report(title="vocab", pid=2 ** 22 + 12345, corpus_dir=os.path.join(self.tmp.name, "c1"))
        self.assertEqual(rep["verdict"], VERDICT_INCONCLUSIVE)
        self.assertEqual(rep["overall_status"], rep["verdict"])
        self.assertIsNone(rep["health_score"])
        self.assertTrue(rep["limitations"])

    def test_export_and_scans_on_a_live_process(self):
        wsm = WatchSessionManager(corpus_dir=os.path.join(self.tmp.name, "c2"))
        rep = wsm.export_incident_report(title="vocab live", pid=self.proc.pid)
        self.assertIn(rep["verdict"], ALL_OVERALL_VERDICTS)
        self.assertEqual(rep["diagnosis"]["verdict"], rep["verdict"])
        tri = wsm.auto_triage_incident(pid=self.proc.pid, companion_elf_path=f"/proc/{self.proc.pid}/exe")
        self.assertIn(tri["overall_status"], ALL_OVERALL_VERDICTS)
        self.assertNotEqual(tri["overall_status"], VERDICT_HEALTHY)  # a scan never certifies health


if __name__ == "__main__":
    unittest.main()
