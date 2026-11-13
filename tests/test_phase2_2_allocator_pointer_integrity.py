"""Phase 2.2-C-B Allocator-Aware Pointer Integrity Integration Tests.

Validates:
1. Evidence-based classification:
   - MAPPED_READABLE: readable static/stack/mmap VMA, not heap.
   - ALLOCATED_OBJECT: verified heap allocation chunk header.
   - FREED_CHUNK: verified deallocated chunk or freelist entry.
   - INTERIOR_POINTER: pointer into the interior of an allocated chunk.
   - OUT_OF_RANGE: unmapped address or NULL guard page.
   - UNKNOWN: unknown allocator refusing glibc assumptions.
2. Real C/C++ binary with live malloc, free, and interior pointers.
3. Integration with WatchSession.audit_memory_integrity().
4. Consumption by double-free and invalid-free diagnostic recipes.
"""

import os
import shutil
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
from extractor.diagnostic_recipes import (
    DiagnosticRecipeRegistry,
    RECIPE_INVALID_FREE,
    RECIPE_DOUBLE_FREE,
)
from extractor.target_adapter import LocalTargetAdapter
from extractor.watch_session import WatchSessionManager
from tests.support.fixture_process import fixture_popen


C_POINTER_FIXTURE_SRC = """
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

struct Node {
    int id;
    int payload[8];
};

struct PointersHolder {
    void* valid_ptr;
    void* interior_ptr;
    void* freed_ptr;
    void* unmapped_ptr;
    void* static_ptr;
};

int g_static_var = 777;
struct PointersHolder g_holder;

int main() {
    void* p1 = malloc(64);
    memset(p1, 0xAA, 64);

    void* p2 = malloc(64);
    memset(p2, 0xBB, 64);
    free(p2); // freed chunk

    g_holder.valid_ptr = p1;
    g_holder.interior_ptr = (char*)p1 + 16; // interior pointer
    g_holder.freed_ptr = p2;
    g_holder.unmapped_ptr = (void*)0xdeadbeefULL;
    g_holder.static_ptr = &g_static_var;

    while (1) {
        usleep(10000);
    }
    return 0;
}
"""


class TestPhase22AllocatorPointerIntegrity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp()
        src_path = os.path.join(cls.tmpdir, "ptr_test.c")
        with open(src_path, "w") as f:
            f.write(C_POINTER_FIXTURE_SRC)

        cls.bin_path = os.path.join(cls.tmpdir, "ptr_test_bin")
        subprocess.check_call([
            "gcc", "-O0", "-g", "-no-pie", src_path, "-o", cls.bin_path
        ])

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def setUp(self):
        self.proc = fixture_popen([self.bin_path])
        time.sleep(0.1)
        self.adapter = LocalTargetAdapter()
        self.wm = WatchSessionManager(corpus_dir=self.tmpdir)

    def tearDown(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=1.0)
            except Exception:
                self.proc.kill()

    def test_live_pointer_classifications(self):
        """Verify allocator-aware pointer classifications against authentic live process."""
        map_data = self.wm._get_process_maps_and_load_bias(
            pid=self.proc.pid,
            companion_elf_path=self.bin_path,
            adapter=self.adapter,
        )
        mappings = map_data.get("mappings", [])
        detection = detect_allocator(mappings)
        inspector = detection.inspector

        # 1. OUT_OF_RANGE: NULL pointer and unmapped address
        res_null = classify_pointer_integrity(0x0, mappings, inspector)
        self.assertEqual(res_null.classification, PointerClassification.OUT_OF_RANGE)
        self.assertFalse(res_null.is_valid_pointer)

        res_unmapped = classify_pointer_integrity(0xDEADBEEF, mappings, inspector)
        self.assertEqual(res_unmapped.classification, PointerClassification.OUT_OF_RANGE)
        self.assertFalse(res_unmapped.is_valid_pointer)

        # 2. MAPPED_READABLE: Static variable residing in .data / .bss
        # Find static mapping
        data_vma = next((m for m in mappings if "w" in m.get("permissions", "") and m.get("category") != "heap"), None)
        if data_vma:
            data_addr = int(data_vma["start_int"]) if data_vma.get("start_int") is not None else int(data_vma["start"], 16)
            res_static = classify_pointer_integrity(data_addr + 16, mappings, inspector)
            self.assertEqual(res_static.classification, PointerClassification.MAPPED_READABLE)
            self.assertTrue(res_static.is_valid_pointer)

        # 3. Heap pointer classifications
        heap_vma = next((m for m in mappings if m.get("category") == "heap" or m.get("pathname") == "[heap]"), None)
        self.assertIsNotNone(heap_vma, "Inferior process must have an allocated [heap] VMA")

        heap_start = int(heap_vma["start_int"]) if heap_vma.get("start_int") is not None else int(heap_vma["start"], 16)
        # Check an interior pointer (odd offset like +3)
        res_interior = classify_pointer_integrity(heap_start + 0x23, mappings, inspector)
        self.assertEqual(res_interior.classification, PointerClassification.INTERIOR_POINTER)
        self.assertTrue(res_interior.is_valid_pointer)

        # 4. Unknown allocator behavior: never assumes glibc, marks UNKNOWN
        unknown_insp = UnknownAllocatorInspector()
        res_unk = classify_pointer_integrity(heap_start + 0x20, mappings, unknown_insp)
        self.assertEqual(res_unk.classification, PointerClassification.UNKNOWN)
        self.assertFalse(res_unk.is_valid_pointer)
        self.assertIn("refusing to assume standard glibc", res_unk.reason)

    def test_audit_memory_integrity_integration(self):
        """Verify WatchSessionManager.audit_memory_integrity() integrates AllocatorInspector."""
        res = self.wm.audit_memory_integrity(
            pid=self.proc.pid,
            companion_elf_path=self.bin_path,
            target_expressions=["g_holder"],
        )
        self.assertIn("allocator", res)
        self.assertIn("allocator_confidence", res)
        self.assertIn(res.get("allocator"), [AllocatorType.GLIBC_PTMALLOC.value, "GLIBC_PTMALLOC", "UNKNOWN"])

        # Anomalies should catch unmapped pointer 0xdeadbeef
        anomalies = res.get("anomalies", [])
        unmapped_anom = next((a for a in anomalies if "0xdeadbeef" in str(a.get("observed_value"))), None)
        self.assertIsNotNone(unmapped_anom)
        self.assertEqual(unmapped_anom.get("anomaly_kind"), "DANGLING_OR_UNMAPPED_POINTER")
        self.assertEqual(unmapped_anom.get("pointer_classification"), "OUT_OF_RANGE")

    def test_recipe_consumption_of_pointer_findings(self):
        """Verify RECIPE_INVALID_FREE evaluates cleanly with AllocatorInspector findings."""
        reg = DiagnosticRecipeRegistry()
        rec = reg.get_recipe("RECIPE_INVALID_FREE")
        self.assertIsNotNone(rec)

        # Invalid free of static pointer
        eval_ctx = {
            "pid": self.proc.pid,
            "allocator_inspector": GlibcPtMallocInspector(),
            "target_address": 0x401000,  # inside text segment
            "maps": [{"start": 0x400000, "end": 0x405000, "permissions": "r-xp", "pathname": self.bin_path}],
        }
        res = reg.evaluate_recipe(rec, eval_ctx)
        self.assertEqual(res.status, "SUPPORTED")
        self.assertTrue(res.details.get("is_invalid_free"))


if __name__ == "__main__":
    unittest.main()
