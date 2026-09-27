"""Unit tests for MemoryRegion and region selection policies."""

import unittest

from extractor.memory_maps import MemoryRegion
from extractor.snapshot_regions import (
    POLICY_ALL_READABLE,
    POLICY_EXECUTABLE,
    POLICY_GLOBAL,
    POLICY_HEAP,
    POLICY_SELECTED,
    POLICY_SHARED_LIBRARY,
    POLICY_STACK,
    filter_regions,
)


class MemoryRegionTests(unittest.TestCase):
    def test_memory_region_properties_and_compat(self):
        r = MemoryRegion(
            start=0x1000,
            end=0x2000,
            permissions="rw-p",
            path="[heap]",
            kind="heap"
        )
        self.assertEqual(r.size, 0x1000)
        self.assertTrue(r.readable)
        self.assertTrue(r.writable)
        self.assertFalse(r.executable)
        self.assertEqual(r.category, "heap")
        self.assertEqual(r.pathname, "[heap]")

        d = r.to_dict()
        self.assertEqual(d["start"], "0x1000")
        self.assertEqual(d["category"], "heap")
        self.assertEqual(d["size"], 4096)

    def test_filter_regions_by_policy(self):
        regions = [
            MemoryRegion(0x1000, 0x2000, "rw-p", "[heap]", "heap"),
            MemoryRegion(0x2000, 0x3000, "rw-p", "[stack]", "stack"),
            MemoryRegion(0x3000, 0x4000, "r-xp", "/bin/app", "executable"),
            MemoryRegion(0x4000, 0x5000, "rw-p", "/bin/app", "global"),
            MemoryRegion(0x5000, 0x6000, "r-xp", "/lib/libc.so", "shared_library"),
            MemoryRegion(0x6000, 0x7000, "---p", "", "anonymous"),  # unreadable
            MemoryRegion(0x7000, 0x8000, "r--p", "[vvar]", "vvar"),  # kernel special
        ]

        # STACK policy
        stack_regs = filter_regions(regions, policy=POLICY_STACK)
        self.assertEqual(len(stack_regs), 1)
        self.assertEqual(stack_regs[0].category, "stack")

        # HEAP policy
        heap_regs = filter_regions(regions, policy=POLICY_HEAP)
        self.assertEqual(len(heap_regs), 1)
        self.assertEqual(heap_regs[0].category, "heap")

        # GLOBAL policy
        global_regs = filter_regions(regions, policy=POLICY_GLOBAL)
        self.assertEqual(len(global_regs), 1)
        self.assertEqual(global_regs[0].category, "global")

        # EXECUTABLE policy
        exec_regs = filter_regions(regions, policy=POLICY_EXECUTABLE)
        self.assertEqual(len(exec_regs), 2)  # /bin/app and /lib/libc.so

        # SHARED_LIBRARY policy
        so_regs = filter_regions(regions, policy=POLICY_SHARED_LIBRARY)
        self.assertEqual(len(so_regs), 1)
        self.assertEqual(so_regs[0].category, "shared_library")

        # ALL_READABLE policy (skips unreadable and [vvar])
        all_regs = filter_regions(regions, policy=POLICY_ALL_READABLE)
        self.assertEqual(len(all_regs), 5)

    def test_filter_regions_selected_and_limits(self):
        regions = [
            MemoryRegion(0x1000, 0x5000, "rw-p", "[heap]", "heap"),  # 16 KB
            MemoryRegion(0x5000, 0x9000, "rw-p", "[stack]", "stack"),  # 16 KB
        ]

        # SELECTED policy with range overlap
        selected = filter_regions(regions, policy=POLICY_SELECTED, selected_ranges=[(0x2000, 0x3000)])
        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0].category, "heap")

        # Max total bytes clamping
        capped = filter_regions(regions, policy=POLICY_ALL_READABLE, max_total_bytes=24 * 1024)
        self.assertEqual(len(capped), 2)
        self.assertEqual(capped[0].size, 16 * 1024)
        self.assertEqual(capped[1].size, 8 * 1024)  # Truncated second region
        self.assertEqual(sum(r.size for r in capped), 24 * 1024)

        # Max region bytes clamping
        clamped = filter_regions(regions, policy=POLICY_ALL_READABLE, max_region_bytes=8 * 1024)
        self.assertEqual(clamped[0].size, 8 * 1024)
        self.assertEqual(clamped[1].size, 8 * 1024)


if __name__ == "__main__":
    unittest.main()
