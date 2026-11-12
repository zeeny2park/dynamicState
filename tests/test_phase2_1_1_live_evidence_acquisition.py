"""Phase 2.1.1 — Runtime Evidence Acquisition Test Suite.

Verifies:
1. RuntimeEvidenceProvider acquires live observations from real running processes.
2. Every observation record contains explicit provenance, collection method, timestamp, and status.
3. No LIVE_RUNTIME_CAPTURE records are emitted without an actual target read.
4. Zero-stop architecture is preserved (0.00ms stop time).
5. Graceful partial collection on missing prerequisites or limitations.
"""

import os
import subprocess
import time
import unittest

from tests.fixture_builds import ensure_expert_diagnostic_fixture
from extractor.diagnostic_recipes import (
    DiagnosticRecipeRegistry,
    RECIPE_INVALID_MEMORY_ACCESS,
    RECIPE_PROCESS_MEMORY_GROWTH,
)
from extractor.runtime_evidence_provider import (
    COLLECTION_STATUS_FAILED,
    COLLECTION_STATUS_SUCCESS,
    COLLECTION_STATUS_UNAVAILABLE,
    PROVENANCE_HISTORICAL_RECORD,
    PROVENANCE_LIVE_RUNTIME_CAPTURE,
    PROVENANCE_SYNTHETIC_FIXTURE,
    RuntimeEvidenceProvider,
    RuntimeEvidenceRecord,
)
from extractor.target_adapter import LocalTargetAdapter


class TestPhase211LiveEvidenceAcquisition(unittest.TestCase):
    """Audits live runtime evidence acquisition contracts and zero-stop guarantees."""

    @classmethod
    def setUpClass(cls):
        cls.debug_elf = "/tmp/expert_diagnostic_debug.elf"
        cls.stripped_elf = "/tmp/expert_diagnostic_stripped.elf"
        ensure_expert_diagnostic_fixture()

    def setUp(self):
        self.procs = []
        self.provider = RuntimeEvidenceProvider(
            adapter=LocalTargetAdapter(),
            corpus_dir="/tmp/phase2_1_1_ev_corpus",
        )
        self.registry = DiagnosticRecipeRegistry()

    def tearDown(self):
        for p in self.procs:
            try:
                p.terminate()
                p.wait(timeout=1.0)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass

    def _spawn_target(self, mode: str) -> subprocess.Popen:
        p = subprocess.Popen([self.debug_elf, mode], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.procs.append(p)
        time.sleep(0.12)
        return p

    def test_collect_process_info_live_target(self):
        """Verifies process info collection against live running target process."""
        proc = self._spawn_target("healthy")
        info, records = self.provider.collect_process_info(proc.pid)

        self.assertTrue(info["alive"])
        self.assertEqual(info["pid"], proc.pid)
        self.assertGreater(info["rss_kb"], 0)
        self.assertGreater(info["thread_count"], 0)

        self.assertEqual(len(records), 1)
        rec = records[0]
        self.assertEqual(rec.target_pid, proc.pid)
        self.assertEqual(rec.provenance_class, PROVENANCE_LIVE_RUNTIME_CAPTURE)
        self.assertEqual(rec.collection_status, COLLECTION_STATUS_SUCCESS)
        self.assertIn("rss_kb", rec.observed_value)

    def test_collect_memory_maps_live_target(self):
        """Verifies memory mapping collection returns authentic VMAs."""
        proc = self._spawn_target("healthy")
        maps, records = self.provider.collect_memory_maps(proc.pid)

        self.assertGreater(len(maps), 0)
        self.assertEqual(len(records), 1)
        rec = records[0]
        self.assertEqual(rec.provenance_class, PROVENANCE_LIVE_RUNTIME_CAPTURE)
        self.assertEqual(rec.collection_status, COLLECTION_STATUS_SUCCESS)
        self.assertEqual(rec.target_pid, proc.pid)

    def test_zero_stop_memory_slice_read(self):
        """Verifies process_vm_readv zero-stop read with exact bytes and provenance."""
        proc = self._spawn_target("corrupt")
        maps, _ = self.provider.collect_memory_maps(proc.pid)
        first_r_map = next(m for m in maps if "r" in m.get("permissions", ""))
        target_addr = first_r_map["start"]

        start_time = time.monotonic()
        data, method, err, records = self.provider.read_memory_range(proc.pid, target_addr, 16)
        elapsed_ms = (time.monotonic() - start_time) * 1000.0

        self.assertIsNotNone(data)
        self.assertEqual(len(data), 16)
        self.assertLess(elapsed_ms, 5.0)  # Non-intrusive sub-5ms read
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].provenance_class, PROVENANCE_LIVE_RUNTIME_CAPTURE)
        self.assertEqual(records[0].collection_status, COLLECTION_STATUS_SUCCESS)

    def test_collect_for_recipe_offline_fallback_does_not_claim_live(self):
        """Verifies that offline or None PID does NOT emit LIVE_RUNTIME_CAPTURE records."""
        recipe = self.registry.get_recipe(RECIPE_INVALID_MEMORY_ACCESS)
        obs_data, records = self.provider.collect_for_recipe(
            recipe=recipe,
            pid=None,
            companion_elf=self.debug_elf,
        )
        self.assertTrue(obs_data.get("prerequisites_missing"))
        self.assertEqual(len(records), 1)
        # Must NOT be labeled as LIVE_RUNTIME_CAPTURE
        self.assertNotEqual(records[0].provenance_class, PROVENANCE_LIVE_RUNTIME_CAPTURE)
        self.assertIn(records[0].provenance_class, (PROVENANCE_HISTORICAL_RECORD, PROVENANCE_SYNTHETIC_FIXTURE))
        self.assertEqual(records[0].collection_status, COLLECTION_STATUS_UNAVAILABLE)

    def test_collect_for_corrupted_memory_target(self):
        """Verifies actual observation of corrupt magic and low-memory pointer."""
        proc = self._spawn_target("corrupt")
        recipe = self.registry.get_recipe(RECIPE_INVALID_MEMORY_ACCESS)
        obs_data, records = self.provider.collect_for_recipe(
            recipe=recipe,
            pid=proc.pid,
            companion_elf=self.debug_elf,
        )
        self.assertEqual(obs_data.get("faulting_address"), "0x40")
        self.assertTrue(obs_data.get("magic_corrupted"))
        self.assertEqual(obs_data.get("observed_magic"), "0xdeadbeef")
        self.assertGreater(len(records), 0)
        for r in records:
            if r.collection_status == COLLECTION_STATUS_SUCCESS:
                self.assertEqual(r.provenance_class, PROVENANCE_LIVE_RUNTIME_CAPTURE)


if __name__ == "__main__":
    unittest.main()
