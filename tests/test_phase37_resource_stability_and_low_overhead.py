"""Phase 37 (Phase 7): Resource & Latency Stabilization Tests.

Verifies that connecting to a local or remote process and performing captures via the Web UI
or Investigation API operates strictly within bounded CPU and memory budgets without
spawning duplicate `objdump`/`readelf`/`nm` subprocess storms or re-parsing JSONL files.
"""

import os
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from extractor.capture_backend import CaptureSafetyPolicy, ProcessVmCaptureBackend
from extractor.debug_image import clear_elf_identity_cache, inspect_elf
from extractor.dwarf_indexer import DwarfIndexer
from extractor.investigation import InvestigationManager
from extractor.static_analyzer import (
    DwarfStaticAnalysisProvider,
    get_static_provider,
    resolve_function_candidates,
)
from extractor.watch_session import WatchSessionManager


class TestPhase37ResourceStabilityAndLowOverhead(unittest.TestCase):
    """Tests for CPU/RAM stabilization across static analysis, DWARF indexing, watch sessions, and live capture."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp_dir = tempfile.mkdtemp(prefix="ds_phase37_")
        cls.src_path = os.path.join(cls.tmp_dir, "target_app.cpp")
        cls.bin_path = os.path.join(cls.tmp_dir, "target_app_nostrip")

        with open(cls.src_path, "w", encoding="utf-8") as f:
            f.write(
                """
#include <stdint.h>
#include <unistd.h>

struct WorkerMetrics {
    int32_t counter;
    int32_t status;
    int32_t error_code;
    int32_t retry_count;
    int32_t noise_a;
    int32_t noise_b;
    int32_t noise_c;
    int32_t noise_d;
};

WorkerMetrics g_metrics = {42, 1, 0, 3, 10, 20, 30, 40};

void update_metrics(int delta) {
    g_metrics.counter += delta;
    g_metrics.status = (g_metrics.counter > 0) ? 1 : 0;
}

int main() {
    update_metrics(1);
    while (true) {
        usleep(50000);
    }
    return 0;
}
"""
            )

        subprocess.run(
            ["g++", "-g", "-O0", cls.src_path, "-o", cls.bin_path],
            check=True,
        )
        cls.proc = subprocess.Popen([cls.bin_path])
        time.sleep(0.15)

    @classmethod
    def tearDownClass(cls) -> None:
        if getattr(cls, "proc", None) and cls.proc.poll() is None:
            cls.proc.terminate()
            try:
                cls.proc.wait(timeout=3)
            except Exception:
                cls.proc.kill()
        shutil.rmtree(cls.tmp_dir, ignore_errors=True)

    def setUp(self) -> None:
        DwarfStaticAnalysisProvider.clear_caches()
        DwarfIndexer.clear_cache()
        clear_elf_identity_cache()

    def test_01_objdump_and_nm_cached_across_repeated_static_analysis(self) -> None:
        """Repeated find_references and resolve_function_candidates calls spawn objdump and nm only once."""
        popen_calls = []
        real_popen = subprocess.Popen

        def counting_popen(cmd, *args, **kwargs):
            if isinstance(cmd, (list, tuple)) and cmd:
                popen_calls.append(cmd[0])
            return real_popen(cmd, *args, **kwargs)

        with patch("extractor.static_analyzer.subprocess.Popen", side_effect=counting_popen):
            prov1 = get_static_provider("dwarf", self.bin_path)
            prov2 = get_static_provider("dwarf", self.bin_path)
            self.assertIs(prov1, prov2)

            for _ in range(15):
                prov1.find_references("update_metrics")
                prov1.find_references("g_metrics")
                prov1.get_call_relationships("update_metrics")
                resolve_function_candidates(
                    target_object={"object_id": "obj_1", "type": "WorkerMetrics", "name": "g_metrics"},
                    target_field={"name": "counter"},
                    static_provider=prov1,
                )

        self.assertEqual(popen_calls.count("nm"), 1, f"Expected 1 nm call, got {popen_calls}")
        self.assertEqual(popen_calls.count("objdump"), 1, f"Expected 1 objdump call, got {popen_calls}")

    def test_02_dwarf_indexer_single_flight_deduplication(self) -> None:
        """Concurrent threads calling DwarfIndexer.get_index on the same binary run readelf --debug-dump=info once."""
        info_calls = []
        real_popen = subprocess.Popen
        lock = threading.Lock()

        def counting_popen(cmd, *args, **kwargs):
            if isinstance(cmd, (list, tuple)) and "--debug-dump=info" in cmd:
                with lock:
                    info_calls.append(cmd)
            return real_popen(cmd, *args, **kwargs)

        results = [None] * 6
        barrier = threading.Barrier(6)

        def worker(idx: int) -> None:
            barrier.wait()
            results[idx] = DwarfIndexer.get_index(self.bin_path, use_disk_cache=False)

        with patch("extractor.dwarf_indexer.subprocess.Popen", side_effect=counting_popen):
            threads = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=10)

        self.assertEqual(len(info_calls), 1, f"Expected single-flight readelf --debug-dump=info, got {len(info_calls)}")
        for r in results:
            self.assertIsNotNone(r)
            self.assertIs(r, results[0])

    def test_03_inspect_elf_and_watch_session_lightweight_maps_cache(self) -> None:
        """inspect_elf caches BinaryIdentity and evaluate_symbol_paths avoids thread/variable enumeration."""
        id1 = inspect_elf(self.bin_path)
        with patch("builtins.open", side_effect=AssertionError("inspect_elf should hit cache")):
            id2 = inspect_elf(self.bin_path)
        self.assertEqual(id1.build_id, id2.build_id)

        corpus_dir = os.path.join(self.tmp_dir, "corpus_watch")
        wm = WatchSessionManager(corpus_dir=corpus_dir)

        with patch.object(
            wm,
            "get_memory_map_and_threads",
            side_effect=AssertionError("evaluate_symbol_paths must not call heavy get_memory_map_and_threads"),
        ):
            res = wm.evaluate_symbol_paths(
                pid=self.proc.pid,
                companion_elf_path=self.bin_path,
                expressions=["g_metrics.counter", "g_metrics.status"],
            )
        results = res.get("results", [])
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["status"], "OBSERVED")
        self.assertEqual(results[0]["value"], 43)

    def test_04_in_memory_observations_ring_buffer_avoids_jsonl_reparsing(self) -> None:
        """get_observations serves active session data from in-memory ring buffer without reading disk JSONL."""
        corpus_dir = os.path.join(self.tmp_dir, "corpus_obs")
        wm = WatchSessionManager(corpus_dir=corpus_dir)
        sess = wm.create_session(
            pid=self.proc.pid,
            companion_elf_path=self.bin_path,
            interval_ms=0,
            capture_mode="MANUAL",
        )
        wm.add_watch_item(sess.session_id, {"name": "g_metrics.counter", "expression": "g_metrics.counter"})
        wm.capture_once(sess.session_id)
        wm.capture_once(sess.session_id)

        orig_open = open

        def guarded_open(file, *args, **kwargs):
            if str(file).endswith("observations.jsonl"):
                raise AssertionError("get_observations should serve from memory without opening observations.jsonl")
            return orig_open(file, *args, **kwargs)

        with patch("builtins.open", side_effect=guarded_open):
            obs_data = wm.get_observations(sess.session_id, limit=50)

        self.assertEqual(obs_data["total_observations"], 2)
        self.assertEqual(len(obs_data["observations"]), 2)

    def test_05_live_investigation_bounded_capture_and_single_enrichment(self) -> None:
        """Live start_investigation bounds region capture sizes and enriches only kept findings once."""
        corpus_dir = os.path.join(self.tmp_dir, "corpus_inv")
        mgr = InvestigationManager(corpus_dir=corpus_dir)

        policy = CaptureSafetyPolicy()
        self.assertEqual(policy.max_region_bytes, 4 * 1024 * 1024)

        enrich_calls = []
        orig_enrich = mgr._enrich_finding_navigation

        def counting_enrich(session, finding, *args, **kwargs):
            enrich_calls.append(finding.finding_id)
            return orig_enrich(session, finding, *args, **kwargs)

        with patch.object(mgr, "_enrich_finding_navigation", side_effect=counting_enrich):
            rep = mgr.start_investigation(
                goal="Verify low-overhead live investigation",
                pid=self.proc.pid,
                debug_image=self.bin_path,
                authorize_target=True,
            )

        self.assertIn(rep["status"], ("COMPLETED", "PARTIAL"))
        # Every finding ID should be enriched at most once (no duplicate re-enrichment in static_linking)
        self.assertEqual(len(enrich_calls), len(set(enrich_calls)), f"Duplicate enrich calls detected: {enrich_calls}")


if __name__ == "__main__":
    unittest.main()
