"""Unit tests for MemorySnapshotSummary model, categorization, and API aggregation."""

import unittest
from extractor.memory_snapshot_summary import (
    categorize_region,
    build_memory_snapshot_summary,
    MemorySnapshotSummary,
)


class TestMemorySnapshotSummary(unittest.TestCase):
    def test_region_categorization(self):
        self.assertEqual(categorize_region("[heap]", "rw-p"), "heap")
        self.assertEqual(categorize_region("[stack]", "rw-p"), "stack")
        self.assertEqual(categorize_region("/lib/aarch64-linux-gnu/libc.so.6", "r-xp"), "shared_library")
        self.assertEqual(categorize_region("/usr/lib/libhelper.so", "rw-p"), "shared_library")
        self.assertEqual(categorize_region("/app/prod_app", "r-xp", is_main_binary=True), "executable")
        self.assertEqual(categorize_region("/app/prod_app", "rw-p", is_main_binary=True), "global")
        self.assertEqual(categorize_region("", "rw-p"), "other")
        self.assertEqual(categorize_region("[anon:my_buf]", "rw-p"), "other")

    def test_build_summary_from_raw_regions(self):
        sample_snapshot = {
            "snapshot_id": "S_TEST_001",
            "capture_mode": "LOW_IMPACT",
            "process": {"binary": "/app/target_bin"},
            "consistency": {
                "duration_us": 12500,
                "partial_reads": ["0x1000-0x2000"],
                "failed_reads": [],
                "mapping_race_detected": True,
            },
            "regions": [
                {"name": "[heap]", "start": 0x10000, "end": 0x20000, "size": 0x10000, "perms": "rw-p"},
                {"name": "[stack]", "start": 0x70000, "end": 0x75000, "size": 0x5000, "perms": "rw-p"},
                {"name": "/lib/libm.so", "start": 0x30000, "end": 0x40000, "size": 0x10000, "perms": "r-xp"},
                {"name": "/app/target_bin", "start": 0x50000, "end": 0x60000, "size": 0x10000, "perms": "r-xp"},
                {"name": "/app/target_bin", "start": 0x60000, "end": 0x62000, "size": 0x2000, "perms": "rw-p"},
            ],
            "persistent": {
                "roots": [{"name": "obj_001", "kind": "global"}],
                "objects": [
                    {
                        "object_id": "obj_001",
                        "type": "Session",
                        "storage": "heap",
                        "fields": [
                            {"name": "status", "type": "int", "value": 1, "object_ref": None},
                            {"name": "buf", "type": "void*", "value": "0x123", "object_ref": "obj_002"},
                        ]
                    },
                    {
                        "object_id": "obj_002",
                        "type": "Buffer",
                        "storage": "heap",
                        "fields": [
                            {"name": "cap", "type": "int", "value": 100, "object_ref": None},
                        ]
                    }
                ]
            },
            "architecture": "aarch64",
            "elf_class": "ELF64",
            "endianness": "little",
        }

        summary = build_memory_snapshot_summary(sample_snapshot)
        self.assertEqual(summary.snapshot_id, "S_TEST_001")
        self.assertEqual(summary.status, "PARTIAL")  # mapping race + partial read
        self.assertEqual(summary.capture_mode, "LOW_IMPACT")
        self.assertEqual(summary.duration_ms, 12.5)
        self.assertTrue(summary.quality.mapping_race_detected)
        self.assertEqual(summary.quality.partial_read_count, 1)

        # Check breakdown
        bd = summary.breakdown
        self.assertEqual(bd.heap_bytes, 0x10000)
        self.assertEqual(bd.stack_bytes, 0x5000)
        self.assertEqual(bd.shared_library_bytes, 0x10000)
        self.assertEqual(bd.executable_bytes, 0x10000)
        self.assertEqual(bd.global_bytes, 0x2000)
        self.assertEqual(bd.total_captured_bytes, 0x10000 + 0x5000 + 0x10000 + 0x10000 + 0x2000)

        # Check objects
        objs = summary.objects
        self.assertEqual(objs.total_objects, 2)
        self.assertEqual(objs.heap_objects, 2)
        self.assertEqual(objs.total_references, 1)
        self.assertGreaterEqual(len(objs.hierarchy_preview), 1)

        # Check quality
        q = summary.quality
        self.assertEqual(q.architecture, "AArch64")
        self.assertEqual(q.pointer_width, "64-bit")
        self.assertEqual(q.endianness, "Little")

    def test_build_summary_uncertainty_handling(self):
        """Unknown metadata must be preserved as UNKNOWN without silent defaults."""
        minimal_snapshot = {
            "snapshot_id": "S_MINIMAL",
            "persistent": {"objects": []},
        }

        summary = build_memory_snapshot_summary(minimal_snapshot)
        self.assertEqual(summary.quality.architecture, "UNKNOWN")
        self.assertEqual(summary.quality.pointer_width, "UNKNOWN")
        self.assertEqual(summary.quality.endianness, "UNKNOWN")
        self.assertEqual(summary.quality.build_id_status, "UNAVAILABLE")
        self.assertEqual(summary.status, "COMPLETE")
        self.assertEqual(summary.breakdown.total_captured_bytes, 0)
        self.assertEqual(summary.captured_memory_status, "NOT_AVAILABLE")

    def test_no_runtime_modules_zero_fallback(self):
        """Never guess runtime_modules[0] as main executable; require is_main_executable == True."""
        snapshot = {
            "snapshot_id": "S_MODULES_TEST",
            "persistent": {"objects": []},
        }
        # Non-main shared libraries
        modules = [
            {
                "name": "libhelper.so",
                "is_main_executable": False,
                "architecture": "x86_64",
                "elf_class": "ELF64",
                "endianness": "little",
                "build_id": "fake_helper_build_id"
            },
            {
                "name": "libc.so.6",
                "is_main_executable": False,
                "architecture": "x86_64",
                "elf_class": "ELF64",
                "endianness": "little",
                "build_id": "fake_libc_build_id"
            }
        ]
        summary = build_memory_snapshot_summary(snapshot, runtime_modules=modules)
        # Without is_main_executable == True, must NOT adopt libhelper.so properties
        self.assertEqual(summary.quality.architecture, "UNKNOWN")
        self.assertEqual(summary.quality.pointer_width, "UNKNOWN")
        self.assertEqual(summary.quality.endianness, "UNKNOWN")
        self.assertEqual(summary.quality.build_id_status, "UNAVAILABLE")
        self.assertIsNone(summary.quality.build_id)

    def test_separation_of_captured_memory_and_object_footprint(self):
        """Do not synthesize captured memory from object counts; keep captured memory and footprint distinct."""
        snapshot = {
            "snapshot_id": "S_OBJ_TEST",
            "persistent": {
                "objects": [
                    {
                        "object_id": "obj_01",
                        "type": "Config",
                        "storage": "heap",
                        "fields": [{"name": "f1", "value": 1}, {"name": "f2", "value": 2}]
                    }
                ]
            }
        }
        summary = build_memory_snapshot_summary(snapshot)
        # Captured physical memory must be 0 and NOT_AVAILABLE
        self.assertEqual(summary.breakdown.total_captured_bytes, 0)
        self.assertEqual(summary.breakdown.heap_bytes, 0)
        self.assertEqual(summary.captured_bytes, 0)
        self.assertEqual(summary.captured_memory_status, "NOT_AVAILABLE")

        # Object footprint is separate
        self.assertEqual(summary.objects.total_objects, 1)
        self.assertEqual(summary.objects.footprint_status, "ESTIMATED")
        self.assertGreater(summary.objects.footprint_bytes, 0)


if __name__ == "__main__":
    unittest.main()
