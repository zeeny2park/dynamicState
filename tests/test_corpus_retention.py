import os
import tempfile
import time
import unittest
from unittest import mock

from extractor import corpus_retention as cr

DAY = 86400.0
MB = 1024 * 1024


def _write(path, size=10, age=0.0):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(b"x" * size)
    t = time.time() - age
    os.utime(path, (t, t))
    return path


class CorpusRetentionTests(unittest.TestCase):
    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.root = td.name

    def test_old_entries_removed_recent_and_in_use_kept(self):
        old = _write(os.path.join(self.root, "investigations", "old.json"), age=10 * DAY)
        mid = _write(os.path.join(self.root, "reports", "mid.report.json"), age=2 * DAY)
        busy = _write(os.path.join(self.root, "investigations", "busy.json"), age=10)
        base = _write(os.path.join(self.root, "golden_baselines", "b.json"), age=30 * DAY)
        removed = cr.prune_corpus(self.root, max_age_days=7, max_mb=0, grace_seconds=3600)
        self.assertEqual(removed, [old])
        self.assertTrue(all(os.path.exists(p) for p in (mid, busy, base)))

    def test_size_cap_removes_oldest_first_but_never_within_grace(self):
        a = _write(os.path.join(self.root, "investigations", "a.json"), MB, age=3 * DAY)
        b = _write(os.path.join(self.root, "investigations", "b.json"), MB, age=2 * DAY)
        c = _write(os.path.join(self.root, "investigations", "c.json"), MB, age=5)
        cr.prune_corpus(self.root, max_age_days=0, max_mb=1, grace_seconds=3600)
        self.assertFalse(os.path.exists(a))
        self.assertFalse(os.path.exists(b))
        self.assertTrue(os.path.exists(c))  # in use: kept even though over the cap

    def test_session_directory_is_one_unit_and_newest_file_counts(self):
        d = os.path.join(self.root, "watch_sessions", "s1")
        _write(os.path.join(d, "old.bin"), age=10 * DAY)
        _write(os.path.join(d, "live.bin"), age=5)
        cr.prune_corpus(self.root, max_age_days=7, max_mb=0, grace_seconds=3600)
        self.assertTrue(os.path.isdir(d))

    def test_explicit_corpus_dir_is_never_pruned(self):
        old = _write(os.path.join(self.root, "investigations", "old.json"), age=100 * DAY)
        with mock.patch.object(cr, "prune_corpus") as pr:
            self.assertEqual(cr.resolve_corpus_dir(self.root), self.root)
        pr.assert_not_called()
        self.assertTrue(os.path.exists(old))

    def test_default_dir_is_pruned_once_per_throttle_window(self):
        with mock.patch.object(cr, "default_corpus_dir", return_value=self.root), \
                mock.patch.object(cr, "prune_corpus") as pr, mock.patch.dict(cr._last_run, clear=True):
            self.assertEqual(cr.resolve_corpus_dir(None), self.root)
            cr.resolve_corpus_dir(None)
        self.assertEqual(pr.call_count, 1)

    def test_vanishing_entries_are_tolerated(self):
        _write(os.path.join(self.root, "investigations", "a.json"), age=10 * DAY)
        real = os.lstat

        def flaky(path, *a, **k):
            if str(path).endswith("a.json"):
                raise FileNotFoundError(path)
            return real(path, *a, **k)
        with mock.patch("os.lstat", side_effect=flaky):
            self.assertEqual(cr.prune_corpus(self.root, max_age_days=1, max_mb=0, grace_seconds=0), [])


class DwarfCacheCapTests(unittest.TestCase):
    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.dir = td.name

    def test_lru_pruning_keeps_recently_used_and_protected(self):
        names = ["dwarf_idx_%d.json" % i for i in range(4)]
        for i, n in enumerate(names):  # 0 is oldest
            _write(os.path.join(self.dir, n), MB, age=(10 - i) * 100)
        os.utime(os.path.join(self.dir, names[0]), None)  # a cache hit refreshes recency
        protect = os.path.join(self.dir, names[1])
        cr.prune_cache_dir(self.dir, max_mb=2, protect=[protect])
        left = sorted(os.listdir(self.dir))
        self.assertIn(names[0], left)
        self.assertIn(names[1], left)
        self.assertNotIn(names[2], left)
        self.assertLessEqual(len(left), 2)

    def test_inflight_tmp_files_survive_stale_ones_go(self):
        fresh = _write(os.path.join(self.dir, "dw_fresh.tmp"), 5, age=10)
        stale = _write(os.path.join(self.dir, "dw_stale.tmp"), 5, age=2 * 3600)
        other = _write(os.path.join(self.dir, "unrelated.txt"), 5, age=9 * DAY)
        cr.prune_cache_dir(self.dir, max_mb=0.000001)
        self.assertTrue(os.path.exists(fresh))
        self.assertFalse(os.path.exists(stale))
        self.assertTrue(os.path.exists(other))

    def test_unbounded_when_cap_is_zero_and_missing_dir_is_fine(self):
        f = _write(os.path.join(self.dir, "dwarf_idx_a.json"), MB, age=100)
        cr.prune_cache_dir(self.dir, max_mb=0)
        self.assertTrue(os.path.exists(f))
        self.assertEqual(cr.prune_cache_dir(os.path.join(self.dir, "nope"), max_mb=1), [])

    def test_env_cap_is_read(self):
        f = _write(os.path.join(self.dir, "dwarf_idx_a.json"), MB, age=100)
        with mock.patch.dict(os.environ, {"DYNAMICSTATE_DWARF_CACHE_MAX_MB": "0.5"}):
            cr.prune_cache_dir(self.dir)
        self.assertFalse(os.path.exists(f))


if __name__ == "__main__":
    unittest.main()
