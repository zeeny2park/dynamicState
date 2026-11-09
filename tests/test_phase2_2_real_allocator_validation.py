"""Phase 2.2-C-B: Real Allocator Pointer Integrity Validation.

End-to-end integration test with a real compiled C inferior:
1. Allocates:
   - Live malloc chunk (ALLOCATED_OBJECT)
   - Freed chunk (FREED_CHUNK)
   - Interior pointer (INTERIOR_POINTER)
   - Static variable pointer (MAPPED_READABLE)
   - Stack variable pointer (MAPPED_READABLE)
   - Anonymous mmap allocation (MAPPED_READABLE)
   - Unmapped pointer 0xdeadbeef (OUT_OF_RANGE)
2. Reads actual pointer values from the running inferior's memory and passes them to
   classify_pointer_integrity(), asserting exact classification outcomes.
3. Verifies UnknownAllocatorInspector classifies heap pointers as UNKNOWN without assuming glibc layout.
4. Verifies WatchSession.audit_memory_integrity() catches unmapped and freed pointers while
   never upgrading UNKNOWN to confirmed corruption.
"""

import os
import shutil
import struct
import subprocess
import tempfile
import time
import unittest

from extractor.allocator_inspector import (
    AllocatorType,
    GlibcPtMallocInspector,
    UnknownAllocatorInspector,
    PointerClassification,
    classify_pointer_integrity,
    detect_allocator,
)
from extractor.target_adapter import LocalTargetAdapter
from extractor.watch_session import WatchSessionManager
from extractor.dwarf_indexer import DwarfIndexer


REAL_ALLOCATOR_C_SRC = """
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>

struct LivePointers {
    void* malloc_ptr;
    void* freed_ptr;
    void* interior_ptr;
    void* static_ptr;
    void* stack_ptr;
    void* mmap_ptr;
    void* unmapped_ptr;
};

int g_my_static_var = 12345;
struct LivePointers g_live_ptrs;

int main() {
    volatile int local_stack_var = 999;

    void* p_alloc = malloc(2048);
    memset(p_alloc, 0x41, 2048);

    void* p_freed = malloc(2048);
    memset(p_freed, 0x42, 2048);
    void* p_barrier = malloc(2048); // Prevents coalescing into top chunk
    memset(p_barrier, 0x43, 2048);
    free(p_freed);

    void* p_mmap = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    g_live_ptrs.malloc_ptr = p_alloc;
    g_live_ptrs.freed_ptr = p_freed;
    g_live_ptrs.interior_ptr = (char*)p_alloc + 24;
    g_live_ptrs.static_ptr = &g_my_static_var;
    g_live_ptrs.stack_ptr = (void*)&local_stack_var;
    g_live_ptrs.mmap_ptr = p_mmap;
    g_live_ptrs.unmapped_ptr = (void*)0xdeadbeefULL;

    while (1) {
        usleep(10000);
    }
    return 0;
}
"""


class TestPhase22RealAllocatorValidation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp()
        cls.src_path = os.path.join(cls.tmpdir, "alloc_inferior.c")
        with open(cls.src_path, "w") as f:
            f.write(REAL_ALLOCATOR_C_SRC)

        cls.bin_path = os.path.join(cls.tmpdir, "alloc_inferior")
        subprocess.check_call([
            "gcc", "-O0", "-g", "-no-pie", cls.src_path, "-o", cls.bin_path
        ])

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def setUp(self):
        self.proc = subprocess.Popen([self.bin_path])
        time.sleep(0.15)
        self.adapter = LocalTargetAdapter()
        self.wm = WatchSessionManager(corpus_dir=self.tmpdir)

    def tearDown(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=1.0)
            except Exception:
                self.proc.kill()

    def test_live_pointer_extraction_and_classification(self):
        """Read actual pointer values from running inferior and verify classifications."""
        pid = self.proc.pid
        idx = DwarfIndexer.get_index(self.bin_path)

        # Locate g_live_ptrs symbol
        var = next((v for v in idx.variables if v.name == "g_live_ptrs"), None)
        self.assertIsNotNone(var, "g_live_ptrs must be present in DWARF")
        var_addr = var.link_time_address
        self.assertIsNotNone(var_addr)

        # Read 7 pointers (56 bytes on 64-bit) from g_live_ptrs
        raw_ptrs, st, err = self.adapter.read_memory(pid, var_addr, 7 * 8)
        self.assertEqual(st, "OBSERVED")
        self.assertIsNotNone(raw_ptrs)
        self.assertEqual(len(raw_ptrs), 56)

        ptrs = struct.unpack("<7Q", raw_ptrs)
        malloc_ptr = ptrs[0]
        freed_ptr = ptrs[1]
        interior_ptr = ptrs[2]
        static_ptr = ptrs[3]
        stack_ptr = ptrs[4]
        mmap_ptr = ptrs[5]
        unmapped_ptr = ptrs[6]

        map_data = self.wm._get_process_maps_and_load_bias(
            pid=pid,
            companion_elf_path=self.bin_path,
            adapter=self.adapter,
        )
        mappings = map_data.get("mappings", [])
        detection = detect_allocator(mappings)
        inspector = detection.inspector
        self.assertEqual(inspector.allocator_type(), AllocatorType.GLIBC_PTMALLOC)

        def _mem_reader(addr: int, sz: int):
            b, s, _ = self.adapter.read_memory(pid, addr, sz)
            return b if s == "OBSERVED" else None

        # 1. malloc_ptr -> ALLOCATED_OBJECT
        res_alloc = classify_pointer_integrity(malloc_ptr, mappings, inspector, memory_reader=_mem_reader)
        self.assertEqual(res_alloc.classification, PointerClassification.ALLOCATED_OBJECT)
        self.assertTrue(res_alloc.is_valid_pointer)

        # 2. interior_ptr -> INTERIOR_POINTER
        res_interior = classify_pointer_integrity(interior_ptr, mappings, inspector, memory_reader=_mem_reader)
        self.assertEqual(res_interior.classification, PointerClassification.INTERIOR_POINTER)
        self.assertTrue(res_interior.is_valid_pointer)

        # 3. static_ptr -> MAPPED_READABLE
        res_static = classify_pointer_integrity(static_ptr, mappings, inspector, memory_reader=_mem_reader)
        self.assertEqual(res_static.classification, PointerClassification.MAPPED_READABLE)
        self.assertTrue(res_static.is_valid_pointer)

        # 4. stack_ptr -> MAPPED_READABLE
        res_stack = classify_pointer_integrity(stack_ptr, mappings, inspector, memory_reader=_mem_reader)
        self.assertEqual(res_stack.classification, PointerClassification.MAPPED_READABLE)
        self.assertTrue(res_stack.is_valid_pointer)

        # 5. mmap_ptr -> MAPPED_READABLE
        res_mmap = classify_pointer_integrity(mmap_ptr, mappings, inspector, memory_reader=_mem_reader)
        self.assertEqual(res_mmap.classification, PointerClassification.MAPPED_READABLE)
        self.assertTrue(res_mmap.is_valid_pointer)

        # 6. unmapped_ptr -> OUT_OF_RANGE
        res_unmapped = classify_pointer_integrity(unmapped_ptr, mappings, inspector, memory_reader=_mem_reader)
        self.assertEqual(res_unmapped.classification, PointerClassification.OUT_OF_RANGE)
        self.assertFalse(res_unmapped.is_valid_pointer)

        # 7. freed_ptr -> FREED_CHUNK
        res_freed = classify_pointer_integrity(freed_ptr, mappings, inspector, memory_reader=_mem_reader)
        self.assertEqual(res_freed.classification, PointerClassification.FREED_CHUNK)
        self.assertFalse(res_freed.is_valid_pointer)

        # 8. Unknown allocator refuses glibc assumptions and classifies heap pointer as UNKNOWN
        unknown_insp = UnknownAllocatorInspector()
        res_unk = classify_pointer_integrity(malloc_ptr, mappings, unknown_insp, memory_reader=_mem_reader)
        self.assertEqual(res_unk.classification, PointerClassification.UNKNOWN)
        self.assertFalse(res_unk.is_valid_pointer)
        self.assertIn("refusing to assume standard glibc", res_unk.reason)

    def test_audit_memory_integrity_preserves_findings_without_false_positives(self):
        """WatchSession.audit_memory_integrity() flags corruptions without misclassifying UNKNOWN."""
        res = self.wm.audit_memory_integrity(
            pid=self.proc.pid,
            companion_elf_path=self.bin_path,
            target_expressions=["g_live_ptrs"],
        )
        self.assertEqual(res["health_status"], "ANOMALIES_DETECTED")
        anomalies = res.get("anomalies", [])

        # Should catch unmapped pointer 0xdeadbeef
        unmapped_anom = next((a for a in anomalies if "0xdeadbeef" in str(a.get("observed_value"))), None)
        self.assertIsNotNone(unmapped_anom)
        self.assertEqual(unmapped_anom["anomaly_kind"], "DANGLING_OR_UNMAPPED_POINTER")
        self.assertEqual(unmapped_anom["pointer_classification"], "OUT_OF_RANGE")

        # Should catch freed pointer
        freed_anom = next((a for a in anomalies if a.get("anomaly_kind") == "USE_AFTER_FREE_POINTER"), None)
        self.assertIsNotNone(freed_anom)
        self.assertEqual(freed_anom["pointer_classification"], "FREED_CHUNK")

        # Must NOT flag valid pointers (malloc, interior, static, stack, mmap)
        valid_expressions = {"g_live_ptrs.malloc_ptr", "g_live_ptrs.interior_ptr", "g_live_ptrs.static_ptr", "g_live_ptrs.stack_ptr", "g_live_ptrs.mmap_ptr"}
        flagged_expressions = {a["expression"] for a in anomalies}
        self.assertTrue(valid_expressions.isdisjoint(flagged_expressions), f"False positives detected on: {valid_expressions & flagged_expressions}")


if __name__ == "__main__":
    unittest.main()
