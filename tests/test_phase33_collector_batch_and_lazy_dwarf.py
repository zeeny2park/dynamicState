"""Phase 33 (Phase 2 Roadmap) Test Suite:
1. Native C99 Collector zero-disk `--read-slices` and persistent `--daemon` stdio RPC modes.
2. RemoteSshTargetAdapter single-roundtrip `read_memory_batch` (both C99 collector and POSIX shell batching).
3. WatchSession dynamic pointer-chain watch items (`g_heap_state->counter`, `g_session.worker.shared->value`) across mutations.
4. Fast `.symtab` symbol scanner (`get_fast_symbol_table`) and persistent on-disk DWARF index caching.
"""

import base64
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from extractor.dwarf_indexer import DwarfIndex, DwarfIndexer
from extractor.target_adapter import RemoteSshTargetAdapter
from extractor.watch_session import WatchSessionManager


class TestPhase33CollectorBatchAndLazyDwarf(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work_dir = tempfile.mkdtemp(prefix="dynstate_p33_")
        cls.corpus_dir = os.path.join(cls.work_dir, "corpus")
        os.makedirs(cls.corpus_dir, exist_ok=True)

        # Build C99 collector
        cls.collector_dir = os.path.join(PROJECT_ROOT, "target", "collector")
        cls.collector_bin = os.path.join(cls.collector_dir, "dynamicstate-collector")
        subprocess.run(["make", "-C", cls.collector_dir], check=True, capture_output=True)

        # Build C++ fixture (PIE + DWARF and stripped production binary, with PR_SET_PTRACER_ANY for sibling collector tests)
        orig_src = os.path.join(PROJECT_ROOT, "tests", "fixtures", "real_runtime", "main.cpp")
        cls.fixture_src = os.path.join(cls.work_dir, "main_ptracer.cpp")
        with open(orig_src, "r", encoding="utf-8") as sf:
            src_code = sf.read()
        ptracer_ctor = """
#include <sys/prctl.h>
__attribute__((constructor)) static void _enable_sibling_collector_ptracer() {
    prctl(0x59616d61, -1, 0, 0, 0);
}
"""
        with open(cls.fixture_src, "w", encoding="utf-8") as df:
            df.write(ptracer_ctor + "\n" + src_code)
        cls.debug_bin = os.path.join(cls.work_dir, "app_debug.elf")
        subprocess.run(
            [
                "g++", "-fPIE", "-pie", "-g", "-O0", "-fno-inline", "-fno-omit-frame-pointer",
                "-Wl,--build-id=sha1", cls.fixture_src, "-o", cls.debug_bin, "-lpthread"
            ],
            check=True,
        )
        cls.stripped_bin = os.path.join(cls.work_dir, "app_prod.stripped")
        subprocess.run(["strip", "-s", "-o", cls.stripped_bin, cls.debug_bin], check=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.work_dir, ignore_errors=True)

    def setUp(self):
        self._procs = []

    def tearDown(self):
        for p in self._procs:
            try:
                p.kill()
                p.wait(timeout=2)
            except Exception:
                pass
            for s in (p.stdin, p.stdout, p.stderr):
                if s:
                    try:
                        s.close()
                    except Exception:
                        pass

    def _start_target(self, bin_path: str) -> subprocess.Popen:
        p = subprocess.Popen(
            [bin_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self._procs.append(p)
        deadline = time.time() + 3.0
        while time.time() < deadline:
            line = p.stdout.readline()
            if "READY" in line:
                break
        return p

    def test_01_native_c99_collector_read_slices_and_daemon_mode(self):
        """Verify C99 collector --read-slices and --daemon modes read live process memory without disk writes."""
        proc = self._start_target(self.stripped_bin)
        mgr = WatchSessionManager(corpus_dir=self.corpus_dir)

        ev = mgr.evaluate_symbol_paths(
            pid=proc.pid,
            companion_elf_path=self.debug_bin,
            expressions=["g_session.worker.state.counter", "g_node_a.value"],
        )
        by_ex = {r["expression"]: r for r in ev["results"]}
        addr_counter = by_ex["g_session.worker.state.counter"]["runtime_address"]
        addr_node = by_ex["g_node_a.value"]["runtime_address"]

        # 1. One-shot --read-slices mode
        spec = f"{addr_counter}:4,{addr_node}:4"
        res = subprocess.run(
            [self.collector_bin, "-p", str(proc.pid), "--read-slices", spec],
            capture_output=True,
            text=True,
            check=True,
        )
        payload = json.loads(res.stdout.strip())
        self.assertTrue(payload["success"])
        self.assertEqual(payload["pid"], proc.pid)
        self.assertEqual(len(payload["slices"]), 2)
        self.assertEqual(payload["slices"][0]["status"], "OBSERVED")
        self.assertEqual(struct.unpack("<i", bytes.fromhex(payload["slices"][0]["hex"]))[0], 42)
        self.assertEqual(struct.unpack("<i", bytes.fromhex(payload["slices"][1]["hex"]))[0], 111)

        # 2. Persistent --daemon stdio RPC mode across live mutation
        daemon = subprocess.Popen(
            [self.collector_bin, "--daemon"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self._procs.append(daemon)

        daemon.stdin.write("PING\n")
        daemon.stdin.flush()
        ping_resp = json.loads(daemon.stdout.readline().strip())
        self.assertEqual(ping_resp.get("status"), "PONG")

        daemon.stdin.write(f"READ {proc.pid} {spec}\n")
        daemon.stdin.flush()
        read1 = json.loads(daemon.stdout.readline().strip())
        self.assertTrue(read1["success"])
        self.assertEqual(struct.unpack("<i", bytes.fromhex(read1["slices"][0]["hex"]))[0], 42)

        # Mutate inferior process
        proc.stdin.write("MUTATE\n")
        proc.stdin.flush()
        while True:
            l = proc.stdout.readline()
            if "MUTATED" in l or not l:
                break

        daemon.stdin.write(f"READ {proc.pid} {spec}\n")
        daemon.stdin.flush()
        read2 = json.loads(daemon.stdout.readline().strip())
        self.assertTrue(read2["success"])
        self.assertEqual(struct.unpack("<i", bytes.fromhex(read2["slices"][0]["hex"]))[0], 100)
        self.assertEqual(struct.unpack("<i", bytes.fromhex(read2["slices"][1]["hex"]))[0], 999)

        daemon.stdin.write("QUIT\n")
        daemon.stdin.flush()
        quit_resp = json.loads(daemon.stdout.readline().strip())
        self.assertEqual(quit_resp.get("status"), "BYE")

    def test_02_remote_ssh_adapter_batch_reads_and_collector_integration(self):
        """Verify RemoteSshTargetAdapter batches multiple slices into a single SSH invocation."""
        ssh_calls = []

        def mock_collector_ssh(cmd_args, timeout):
            ssh_calls.append(cmd_args[-1])
            resp = {
                "success": True,
                "pid": 500,
                "backend": "process_vm_readv",
                "slices": [
                    {"address": "0x55001000", "size": 4, "bytes_read": 4, "status": "OBSERVED", "hex": "2a000000"},
                    {"address": "0x55002000", "size": 4, "bytes_read": 4, "status": "OBSERVED", "hex": "6f000000"},
                ],
                "duration_us": 12.5,
            }
            return 0, json.dumps(resp) + "\n", ""

        adapter_coll = RemoteSshTargetAdapter(
            host="10.0.0.50",
            user="root",
            collector_path="/usr/bin/dynamicstate-collector",
            command_runner=mock_collector_ssh,
        )
        res_coll = adapter_coll.read_memory_batch(500, [(0x55001000, 4), (0x55002000, 4)])
        self.assertEqual(len(ssh_calls), 1, "Expected exactly 1 SSH call for batch collector read")
        self.assertIn("--read-slices", ssh_calls[0])
        self.assertEqual(res_coll[0], (struct.pack("<i", 42), "OBSERVED", None))
        self.assertEqual(res_coll[1], (struct.pack("<i", 111), "OBSERVED", None))

        # Now test POSIX shell batch fallback (without collector_path)
        shell_calls = []

        def mock_shell_ssh(cmd_args, timeout):
            shell_calls.append(cmd_args[-1])
            b0 = base64.b64encode(struct.pack("<i", 42)).decode("ascii")
            b1 = base64.b64encode(struct.pack("<i", 111)).decode("ascii")
            return 0, f"0|{b0}\n1|{b1}\n", ""

        adapter_sh = RemoteSshTargetAdapter(
            host="10.0.0.50",
            user="root",
            command_runner=mock_shell_ssh,
        )
        res_sh = adapter_sh.read_memory_batch(500, [(0x55001000, 4), (0x55002000, 4)])
        self.assertEqual(len(shell_calls), 1, "Expected exactly 1 SSH call for batched shell read")
        self.assertEqual(res_sh[0], (struct.pack("<i", 42), "OBSERVED", None))
        self.assertEqual(res_sh[1], (struct.pack("<i", 111), "OBSERVED", None))

    def test_03_watch_session_dynamic_pointer_chain_items_and_mutation(self):
        """Verify WatchSession tracks dynamic pointer-chain expressions (ptr->field) across mutations."""
        proc = self._start_target(self.stripped_bin)
        mgr = WatchSessionManager(corpus_dir=self.corpus_dir)

        session = mgr.create_session(
            pid=proc.pid,
            companion_elf_path=self.debug_bin,
            interval_ms=0,
            capture_mode="MANUAL",
        )

        # Add pointer-chain expressions with address=0 (auto-resolved and dynamically evaluated per capture)
        item_shared = mgr.add_watch_item(session.session_id, {
            "name": "g_session.worker.shared->value",
            "expression": "g_session.worker.shared->value",
            "address": 0,
            "scope": "expression",
        })
        item_heap = mgr.add_watch_item(session.session_id, {
            "name": "g_heap_state->counter",
            "expression": "g_heap_state->counter",
            "address": 0,
            "scope": "expression",
        })
        self.assertGreater(item_shared.address, 0)
        self.assertGreater(item_heap.address, 0)

        # Capture #1 (before mutation)
        obs1 = mgr.capture_once(session.session_id)
        self.assertEqual(obs1.values[item_shared.item_id]["value"], 111)
        self.assertEqual(obs1.values[item_heap.item_id]["value"], 99)

        # Trigger live mutation
        proc.stdin.write("MUTATE\n")
        proc.stdin.flush()
        while True:
            l = proc.stdout.readline()
            if "MUTATED" in l or not l:
                break

        # Capture #2 (after mutation)
        obs2 = mgr.capture_once(session.session_id)
        self.assertEqual(obs2.values[item_shared.item_id]["value"], 999)
        self.assertEqual(obs2.values[item_heap.item_id]["value"], 99)

        # Compare observations #1 and #2
        cmp_res = mgr.compare_observations(session.session_id, 1, 2)
        diffs_by_name = {d["name"]: d for d in cmp_res["diffs"]}
        self.assertEqual(diffs_by_name["g_session.worker.shared->value"]["state"], "CHANGED")
        self.assertEqual(diffs_by_name["g_session.worker.shared->value"]["value_a"], 111)
        self.assertEqual(diffs_by_name["g_session.worker.shared->value"]["value_b"], 999)
        self.assertEqual(diffs_by_name["g_heap_state->counter"]["state"], "UNCHANGED")

    def test_04_fast_symbol_table_and_persistent_disk_dwarf_cache(self):
        """Verify fast .symtab scanning and persistent disk caching in DwarfIndexer."""
        cache_dir = tempfile.mkdtemp(prefix="dynstate_dw_cache_")
        try:
            with patch.dict(os.environ, {"DYNAMICSTATE_DWARF_CACHE_DIR": cache_dir}):
                DwarfIndexer.clear_cache()

                # 1. Stage-1 fast symbol table scan
                fast_syms = DwarfIndexer.get_fast_symbol_table(self.debug_bin, load_bias=0x55000000)
                sym_names = {s["name"]: s for s in fast_syms}
                self.assertIn("g_session", sym_names)
                self.assertIn("g_node_a", sym_names)
                self.assertEqual(sym_names["g_session"]["symbol_type"], "OBJECT")
                self.assertGreater(sym_names["g_session"]["runtime_address_int"], 0x55000000)

                # 2. First get_index builds index and populates disk cache
                idx1 = DwarfIndexer.get_index(self.debug_bin, use_disk_cache=True)
                cache_files = os.listdir(cache_dir)
                self.assertEqual(len(cache_files), 1)

                # 3. Clear in-memory cache and verify second get_index loads from disk without calling _build_index
                DwarfIndexer.clear_cache()
                with patch.object(DwarfIndexer, "_build_index", side_effect=AssertionError("_build_index should not be called on disk cache hit")):
                    idx2 = DwarfIndexer.get_index(self.debug_bin, use_disk_cache=True)

                self.assertEqual(idx1.build_id, idx2.build_id)
                self.assertEqual(len(idx1.variables), len(idx2.variables))
                self.assertIn("g_session", idx2.variables_by_name)
                self.assertIn("Session", idx2.types_by_name)
        finally:
            shutil.rmtree(cache_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
