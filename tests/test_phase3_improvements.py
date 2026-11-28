"""Phase 3 unit tests:
1. TrackingLedgerStore concurrent playbook slot isolation & flock merge.
2. diagnose() broad-screening fallback when narrow symptom yields INCONCLUSIVE.
3. Remote SSH Tier-2 sampling & coverage reporting precision.
"""

import os
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

try:
    import pytest
    pytestmark = pytest.mark.unit
except ImportError:  # pragma: no cover
    pass

from extractor.diagnostic_playbooks import select_playbook
from extractor.expert_diagnostic_engine import _new_diagnose_result, diagnose
from extractor.state_intelligence import build_inconclusive_drilldown, classify_coverage
from extractor.tracking_ledger import TrackingLedgerStore, make_target_key


class TestTrackingLedgerConcurrentPlaybookSlots(unittest.TestCase):
    def test_concurrent_distinct_playbooks_preserved_across_stores(self):
        with tempfile.TemporaryDirectory() as td:
            tkey = make_target_key(1234)
            store_a = TrackingLedgerStore(persist_dir=td)
            store_b = TrackingLedgerStore(persist_dir=td)

            pb_mem = select_playbook(symptom="memory leak")
            pb_hang = select_playbook(symptom="deadlock hang")

            la = store_a.get_or_create(tkey)
            la.activate_playbook(pb_mem)
            la.record("runtime_heap_leak_candidates", {"pid": 1234}, {"success": True, "total_candidates": 2})
            self.assertTrue(store_a.save(tkey))

            lb = store_b.get_or_create(tkey)
            lb.activate_playbook(pb_hang)
            lb.record("runtime_inspect_thread_callstack_and_locks", {"pid": 1234}, {"success": True, "threads": []})
            self.assertTrue(store_b.save(tkey))

            # Reload from a fresh store after both writers persisted
            store_c = TrackingLedgerStore(persist_dir=td)
            lc = store_c.get(tkey)
            self.assertIsNotNone(lc)
            slots = lc.list_playbook_slots()
            self.assertIn(pb_mem["playbook_id"], slots)
            self.assertIn(pb_hang["playbook_id"], slots)
            self.assertEqual(lc.get_playbook_slot(pb_mem["playbook_id"])["iteration"], 1)
            self.assertEqual(lc.get_playbook_slot(pb_hang["playbook_id"])["iteration"], 1)

    def test_save_merges_disjoint_playbook_slot_written_concurrently(self):
        with tempfile.TemporaryDirectory() as td:
            tkey = make_target_key(5678)
            store_a = TrackingLedgerStore(persist_dir=td)
            store_b = TrackingLedgerStore(persist_dir=td)

            pb_mem = select_playbook(symptom="memory leak")
            pb_fd = select_playbook(symptom="fd leak")

            # Both stores start before either saves
            la = store_a.get_or_create(tkey)
            lb = store_b.get_or_create(tkey)

            la.activate_playbook(pb_mem)
            self.assertTrue(store_a.save(tkey))

            # Store B activates a different playbook and saves with same/lower initial revision
            lb.activate_playbook(pb_fd)
            self.assertTrue(store_b.save(tkey))

            reloaded = TrackingLedgerStore(persist_dir=td).get(tkey)
            self.assertIsNotNone(reloaded)
            self.assertIn(pb_mem["playbook_id"], reloaded.list_playbook_slots())
            self.assertIn(pb_fd["playbook_id"], reloaded.list_playbook_slots())

    def test_parallel_barrier_save_same_revision_different_slots_preserves_both(self):
        with tempfile.TemporaryDirectory() as td:
            tkey = make_target_key(9012)
            pb_a = select_playbook(symptom="memory leak")
            pb_b = select_playbook(symptom="deadlock hang")

            # Seed initial ledger with both {A, B} slots at equal baseline revision
            seed = TrackingLedgerStore(persist_dir=td)
            l_seed = seed.get_or_create(tkey)
            l_seed.activate_playbook(pb_a)
            l_seed.activate_playbook(pb_b)
            self.assertTrue(seed.save(tkey))

            # Two independent stores load the same {A, B} snapshot, then each updates a disjoint slot
            # to the exact same ledger revision and saves concurrently behind a Barrier.
            store_a = TrackingLedgerStore(persist_dir=td)
            store_b = TrackingLedgerStore(persist_dir=td)
            la = store_a.get_or_create(tkey)
            lb = store_b.get_or_create(tkey)
            self.assertEqual(la.revision, lb.revision)

            la.active_playbook = dict(pb_a)
            la.record("runtime_heap_leak_candidates", {"pid": 9012}, {"success": True, "total_candidates": 4})

            lb.active_playbook = dict(pb_b)
            lb.record("runtime_inspect_thread_callstack_and_locks", {"pid": 9012}, {"success": True, "threads": []})

            self.assertEqual(la.revision, lb.revision)

            barrier = threading.Barrier(2)

            def _worker(store):
                barrier.wait(timeout=5.0)
                return store.save(tkey)

            with ThreadPoolExecutor(max_workers=2) as pool:
                fa = pool.submit(_worker, store_a)
                fb = pool.submit(_worker, store_b)
                self.assertTrue(fa.result(timeout=10.0))
                self.assertTrue(fb.result(timeout=10.0))

            final = TrackingLedgerStore(persist_dir=td).get(tkey)
            self.assertIsNotNone(final)
            slot_a = final.get_playbook_slot(pb_a["playbook_id"])
            slot_b = final.get_playbook_slot(pb_b["playbook_id"])
            self.assertIsNotNone(slot_a)
            self.assertIsNotNone(slot_b)
            self.assertGreater(slot_a["revision"], l_seed.revision)
            self.assertGreater(slot_b["revision"], l_seed.revision)


class TestDiagnoseBroadScreeningFallback(unittest.TestCase):
    def test_narrow_inconclusive_triggers_broad_fallback_and_finds_fault(self):
        narrow_res = _new_diagnose_result(42, None)
        narrow_res.verdict = "INCONCLUSIVE"
        narrow_res.findings = []

        broad_res = _new_diagnose_result(42, None)
        broad_res.verdict = "CONFIRMED_FAULT"
        broad_res.findings = [{"category": "DEADLOCK_INDICATORS", "subjects": ["m_out", "m_in"]}]
        broad_res.summary = "Confirmed deadlock between m_out and m_in."

        calls = []

        def fake_run(pid, debug_image, symptom, **kwargs):
            calls.append(symptom)
            return narrow_res if symptom != "general health check" else broad_res

        with patch("extractor.expert_diagnostic_engine._diagnose_run", side_effect=fake_run):
            out = diagnose(42, symptom="slow database queries")

        self.assertEqual(calls, ["slow database queries", "general health check"])
        self.assertEqual(out.verdict, "CONFIRMED_FAULT")
        self.assertIn("broad-screening fallback", out.summary)

    def test_hard_blocker_skips_broad_fallback(self):
        blocked_res = _new_diagnose_result(42, None)
        blocked_res.verdict = "INCONCLUSIVE"
        blocked_res.not_covered = [{"kind": "target_unreadable", "item": "pid 42", "reason": "Permission denied"}]

        calls = []

        def fake_run(pid, debug_image, symptom, **kwargs):
            calls.append(symptom)
            return blocked_res

        with patch("extractor.expert_diagnostic_engine._diagnose_run", side_effect=fake_run):
            out = diagnose(42, symptom="slow database queries")

        self.assertEqual(calls, ["slow database queries"])
        self.assertEqual(out.verdict, "INCONCLUSIVE")


class TestRemoteTier2CoveragePrecision(unittest.TestCase):
    def test_remote_coverage_and_drilldown_distinguish_link_budget_cap(self):
        res = {
            "verdict": "INCONCLUSIVE",
            "symptom": "memory leak",
            "target": {"pid": 900, "transport": "ssh", "host": "192.0.2.10"},
            "checks_run": [{"recipe_id": "HEAP_RETENTION", "status": "INCONCLUSIVE"}],
            "not_covered": [
                {"kind": "integrity_not_checked", "item": "heap_integrity", "reason": "remote link budget cap"},
                {"kind": "remote_limitation", "item": "tls_tcb", "reason": "TLS/TCB discovery unavailable over SSH"},
            ],
            "healthy_scope": {"blocking": [], "not_checked": []},
        }
        cov = classify_coverage(res)
        rc = cov["detail"]["remote_coverage"]
        self.assertTrue(rc["is_remote"])
        self.assertTrue(rc["heap_walk_capped_by_link_budget"])
        self.assertEqual(rc["remote_limitations_count"], 1)

        dd = build_inconclusive_drilldown(
            res,
            coverage=cov,
            suggested_actions=[{
                "id": "heap_leaks",
                "mcp_tool": "runtime_heap_leak_candidates",
                "mcp_args": {"pid": 900},
                "reason_en": "narrow heap",
            }],
            lang="en",
        )
        codes = {c["cause_code"] for c in dd["causes"]}
        self.assertIn("remote_heap_tiered_sampling", codes)
        self.assertIn("remote_limitation", codes)
        self.assertNotIn("large_heap_tiered_sampling", codes)
        self.assertIn("Recommended playbook:", dd["agent_directive"])


if __name__ == "__main__":
    unittest.main()
