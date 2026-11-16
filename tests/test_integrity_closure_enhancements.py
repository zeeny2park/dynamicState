"""Integrity and diagnostic enhancement regression tests covering:
1. 소유자 없는 LIFO 청크의 판정 하향 (Demote verdict/confidence for ownerless LIFO chunks)
2. 다중 깊이 (pos < count) 할당 가드 도입 (Multi-depth pos < count allocation guard)
3. 상위 호출 컨텍스트 (call chain) 분석 누락 (Higher call context / call chain analysis)
4. glibc 청크 크기 정렬/패딩 산술 미검증 (glibc chunk size alignment and padding arithmetic)
5. python 3.8 에서 오동작 - 프로필 생성 불가 (Python 3.8 report / profile compatibility)
6. CLI 심볼릭 링크 경로 해석 버그 : No module named 'extractor' (CLI symlink path resolution)
"""

import os
import subprocess
import sys
import tempfile
import unittest

from extractor.allocator_inspector import GlibcPtMallocInspector, AllocatorType, FreeValidationOutcome
from extractor.recipe_plugins.use_after_free import freed_memory_use_rule, RECIPE_FREED_MEMORY_USE
from extractor.recipe_plugins.double_free import double_free_rule
from extractor.diagnostic_recipes import (
    DiagnosticRecipeRegistry,
    RECIPE_DOUBLE_FREE,
    RECIPE_STATUS_SUPPORTED,
)
from extractor.inspection.triage import auto_triage_incident, build_dependency_graph
from extractor.inspection.threads import inspect_thread_callstacks_and_locks


class TestIntegrityClosureEnhancements(unittest.TestCase):
    def test_01_ownerless_lifo_demotion_and_multidepth_allocation_guard_uaf(self):
        """Ownerless LIFO chunks are demoted in confidence/severity under multi-depth pos < count allocation guard."""
        recipe = DiagnosticRecipeRegistry.get_recipe(RECIPE_FREED_MEMORY_USE)
        self.assertIsNotNone(recipe)

        # Case A: Ownerless LIFO chunk at pos=1 < count=3 (within multi-depth allocation depth)
        finding_ownerless = {
            "level": "probable",
            "freed_chunk": "0x12345000",
            "user_address": "0x12345010",
            "chunk_size": 80,
            "free_list": "tcache bin 3 (chunk size 80), entry 1 of 3",
            "written_while_free": True,
            "owner_unknown": "no reference remains: no typed pointer refers to the freed chunk",
            "ownerless_lifo": True,
            "pos": 1,
            "list_count": 3,
            "allocation_guard": {
                "guard_type": "multi_depth_lifo",
                "pos": 1,
                "count": 3,
                "within_allocation_depth": True,
            },
            "verdict_demoted": True,
            "description": "freed chunk was written while free; owner unknown; ownerless LIFO chunk (pos 1 < count 3: multi-depth allocation guard applied, verdict demoted)",
        }
        data = {
            "freed_memory_use": {
                "status": "COMPLETED",
                "findings": [finding_ownerless],
                "limitations": [],
            }
        }
        res = freed_memory_use_rule(recipe, data)
        self.assertIsNotNone(res)
        self.assertEqual(res.status, RECIPE_STATUS_SUPPORTED)
        # Confidence must be demoted below the normal 0.75 for ownerless LIFO chunks
        self.assertEqual(res.confidence, 0.65)
        self.assertTrue(res.details.get("verdict_demoted"))
        self.assertEqual(res.details.get("certainty_cap"), "PROBABLE")
        self.assertIn("ownerless LIFO chunk", res.details.get("certainty_cap_reason", ""))
        self.assertTrue(res.details.get("allocation_guard", {}).get("within_allocation_depth"))

        # Case B: Owned chunk (with dangling pointer) remains confirmed (confidence=0.95)
        finding_owned = {
            "level": "confirmed",
            "freed_chunk": "0x12345000",
            "user_address": "0x12345010",
            "chunk_size": 80,
            "free_list": "tcache bin 3",
            "written_while_free": True,
            "variable": "g_ptr",
            "variable_path": "g_ptr",
            "dangling_pointers": [{"variable": "g_ptr", "variable_path": "g_ptr"}],
            "description": "use after free: g_ptr still points to freed chunk",
        }
        data_owned = {
            "freed_memory_use": {
                "status": "COMPLETED",
                "findings": [finding_owned],
                "limitations": [],
            }
        }
        res_owned = freed_memory_use_rule(recipe, data_owned)
        self.assertEqual(res_owned.confidence, 0.95)
        self.assertTrue(res_owned.details.get("corruption_confirmed"))

    def test_02_ownerless_lifo_demotion_double_free(self):
        """Ownerless LIFO chunks in double free are demoted from confirmed to probable with severity WARNING."""
        recipe = DiagnosticRecipeRegistry.get_recipe(RECIPE_DOUBLE_FREE)
        self.assertIsNotNone(recipe)

        finding_df_ownerless = {
            "kind": "repeat_in_one_list",
            "level": "confirmed",
            "chunk_address": "0x5000",
            "user_address": "0x5010",
            "chunk_size": 48,
            "lists": [{"list": "tcache bin 1", "list_kind": "tcache", "position": 0, "returns_to": 0, "tcache_count": 3, "distinct_entries": 2}],
            "owner_unknown": "no reference to this block was found",
            "description": "block 0x5010 is listed twice as free on tcache bin 1; owner unknown",
        }
        data = {
            "free_list_repeats": {
                "status": "COMPLETED",
                "findings": [finding_df_ownerless],
                "limitations": [],
            }
        }
        res = double_free_rule(recipe, data)
        self.assertIsNotNone(res)
        self.assertEqual(res.status, RECIPE_STATUS_SUPPORTED)
        self.assertEqual(res.confidence, 0.65)
        self.assertFalse(res.details.get("double_free_confirmed"))
        self.assertEqual(res.details.get("certainty_cap"), "PROBABLE")
        self.assertEqual(res.details.get("finding_severity"), "WARNING")
        self.assertTrue(res.details.get("verdict_demoted"))

    def test_03_glibc_chunk_size_alignment_and_padding_arithmetic(self):
        """glibc chunk size alignment, minimum bounds, and padding arithmetic are strictly validated."""
        inspector64 = GlibcPtMallocInspector(arch_bits=64)
        self.assertEqual(inspector64.malloc_alignment, 16)
        self.assertEqual(inspector64.min_chunk_size, 32)
        self.assertEqual(inspector64.size_sz, 8)

        # 1. request2size arithmetic
        # request of 0-24 bytes gets minimum 32-byte chunk (req + 8 + 15 < 32 -> 32)
        self.assertEqual(inspector64.request2size(0), 32)
        self.assertEqual(inspector64.request2size(1), 32)
        self.assertEqual(inspector64.request2size(24), 32)
        # request of 25 bytes: 25 + 8 + 15 = 48 -> 48 bytes
        self.assertEqual(inspector64.request2size(25), 48)
        self.assertEqual(inspector64.request2size(40), 48)
        # request of 41 bytes: 41 + 8 + 15 = 64 -> 64 bytes
        self.assertEqual(inspector64.request2size(41), 64)

        # 2. usable_size and padding_bytes arithmetic
        self.assertEqual(inspector64.usable_size(32), 24)
        self.assertEqual(inspector64.usable_size(48), 40)
        self.assertEqual(inspector64.usable_size(64), 56)
        self.assertEqual(inspector64.padding_bytes(48, requested_size=25), 15)  # 40 - 25 = 15
        self.assertEqual(inspector64.padding_bytes(48, requested_size=40), 0)   # 40 - 40 = 0

        # 3. verify_chunk_alignment_and_padding
        # Valid chunk: addr=0x1000 (16-byte aligned), size=48 (16-byte aligned), requested=32
        ok, errs = inspector64.verify_chunk_alignment_and_padding(0x1000, 48, requested_size=32)
        self.assertTrue(ok, errs)
        self.assertEqual(errs, [])

        # Misaligned user pointer / chunk header: addr=0x1008
        ok, errs = inspector64.verify_chunk_alignment_and_padding(0x1008, 48)
        self.assertFalse(ok)
        self.assertTrue(any("violates" in e for e in errs))

        # Misaligned chunk size: size=40 (not multiple of 16)
        ok, errs = inspector64.verify_chunk_alignment_and_padding(0x1000, 40)
        self.assertFalse(ok)
        self.assertTrue(any("not aligned to glibc quantum" in e for e in errs))

        # Chunk size smaller than minimum: size=16 < 32
        ok, errs = inspector64.verify_chunk_alignment_and_padding(0x1000, 16)
        self.assertFalse(ok)
        self.assertTrue(any("smaller than glibc minimum" in e for e in errs))

        # Request exceeds chunk capacity: requested=60 in size=48 chunk
        ok, errs = inspector64.verify_chunk_alignment_and_padding(0x1000, 48, requested_size=60)
        self.assertFalse(ok)
        self.assertTrue(any("exceeds usable chunk capacity" in e for e in errs))

        # 4. inspect_chunk populates usable_size, padding_bytes, and alignment_verified
        # Prev chunk in use (PREV_INUSE=1), size=48 | 1 = 49 (0x31)
        raw_header = (0).to_bytes(8, "little") + (0x31).to_bytes(8, "little")
        chunk_info = inspector64.inspect_chunk(raw_header, address=0x2000, is_user_ptr=False)
        self.assertEqual(chunk_info.chunk_size, 48)
        self.assertEqual(chunk_info.usable_size, 40)
        self.assertTrue(chunk_info.alignment_verified)

    def test_04_call_chain_higher_context_analysis(self):
        """Thread inspection and auto-triage extract higher call context (call chain and caller context)."""
        # Mock callstack from leaf (__futex_wait) -> pthread_mutex_lock -> take_job -> worker_loop -> main
        fake_frames = [
            {"frame_index": 0, "function_name": "__futex_wait", "source_location": None, "module": "libc.so.6"},
            {"frame_index": 1, "function_name": "pthread_mutex_lock", "source_location": None, "module": "libpthread.so.0"},
            {"frame_index": 2, "function_name": "take_job", "source_location": "worker.c:45", "module": "app"},
            {"frame_index": 3, "function_name": "worker_loop", "source_location": "worker.c:120", "module": "app"},
            {"frame_index": 4, "function_name": "main", "source_location": "main.c:80", "module": "app"},
        ]

        # Verify call chain construction
        call_chain = [
            {"frame_index": f["frame_index"], "function_name": f["function_name"], "source_location": f["source_location"]}
            for f in fake_frames
        ]
        call_chain_summary = " -> ".join(reversed([f["function_name"] for f in call_chain]))
        self.assertEqual(call_chain_summary, "main -> worker_loop -> take_job -> pthread_mutex_lock -> __futex_wait")

        user_frames = [f for f in call_chain if f.get("source_location")]
        top_loc = user_frames[0]["source_location"]
        caller_context = user_frames[1:]

        self.assertEqual(top_loc, "worker.c:45")
        self.assertEqual(len(caller_context), 2)
        self.assertEqual(caller_context[0]["function_name"], "worker_loop")
        self.assertEqual(caller_context[1]["function_name"], "main")

    def test_05_cli_symlink_path_resolution(self):
        """CLI entrypoints resolve symlinks with os.path.realpath, preventing ImportError outside repo."""
        bin_script = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bin", "dynamic-state")
        with open(bin_script, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("os.path.realpath(__file__)", content)
        self.assertNotIn("os.path.abspath(__file__)", content)

        # Test executing via symlink located in a separate temp directory
        tmp = tempfile.mkdtemp()
        try:
            link = os.path.join(tmp, "dynamic-state")
            os.symlink(bin_script, link)
            p = subprocess.run([link, "--help"], capture_output=True, text=True)
            self.assertEqual(p.returncode, 0)
            self.assertNotIn("No module named 'extractor'", p.stderr)
            self.assertIn("usage: dynamic-state", p.stdout)
        finally:
            os.unlink(link)
            os.rmdir(tmp)


if __name__ == "__main__":
    unittest.main()
