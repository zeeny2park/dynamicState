"""Unit tests for OfflineMemoryAnalyzer."""

import os
import shutil
import struct
import tempfile
import unittest

from extractor.debug_image import DebugImageProvider
from extractor.memory_snapshot import CapturedRegion, RawMemorySnapshot
from extractor.offline_analyzer import OfflineMemoryAnalyzer
from extractor.snapshot import RuntimeSnapshot
from extractor.state_hash import compute_state_hash


class OfflineMemoryAnalyzerTests(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="test_offline_ana_")
        mem_dir = os.path.join(self.tmp_dir, "memory")
        os.makedirs(mem_dir, exist_ok=True)

        # Build synthetic memory:
        # 1. Global pointer at 0x20018: points to heap session at 0x5000
        # 2. Heap Session object at 0x5000 (size 48):
        #    offset 0: state (uint32 enum = 1 -> "SessionState::CONNECTED")
        #    offset 4: retry (uint32 = 3)
        #    offset 8: packet_count (uint32 = 123)
        #    offset 16: buffer ptr (0x6000)
        #    offset 24: parent ptr (0x5000 -> self cycle)
        #    offset 32: flagged (bool = 1)
        #    offset 33: priority (uint8 = 7)
        #    offset 40: ratio (double = 2.5)
        # 3. Heap Buffer object at 0x6000 (size 16):
        #    offset 0: length (uint32 = 64)
        #    offset 4: capacity (uint32 = 256)
        #    offset 8: data ptr (0x0)

        # Region 1: Global binary data (0x20000 - 0x21000)
        global_buf = bytearray(0x1000)
        struct.pack_into("<Q", global_buf, 0x18, 0x5000)  # global_session = 0x5000
        with open(os.path.join(mem_dir, "region_global.bin"), "wb") as f:
            f.write(global_buf)

        # Region 2: Heap (0x5000 - 0x7000)
        heap_buf = bytearray(0x2000)
        # Session at 0x5000 (offset 0 in heap_buf)
        struct.pack_into("<I", heap_buf, 0, 1)              # state = 1
        struct.pack_into("<I", heap_buf, 4, 3)              # retry = 3
        struct.pack_into("<I", heap_buf, 8, 123)            # packet_count = 123
        struct.pack_into("<Q", heap_buf, 16, 0x6000)        # buffer = 0x6000
        struct.pack_into("<Q", heap_buf, 24, 0x5000)        # parent = 0x5000 (self)
        heap_buf[32] = 1                                    # flagged = true
        heap_buf[33] = 7                                    # priority = 7
        struct.pack_into("<d", heap_buf, 40, 2.5)           # ratio = 2.5

        # Buffer at 0x6000 (offset 0x1000 in heap_buf)
        struct.pack_into("<I", heap_buf, 0x1000, 64)        # length = 64
        struct.pack_into("<I", heap_buf, 0x1004, 256)       # capacity = 256
        struct.pack_into("<Q", heap_buf, 0x1008, 0)         # data = 0

        with open(os.path.join(mem_dir, "region_heap.bin"), "wb") as f:
            f.write(heap_buf)

        self.reg_global = CapturedRegion(
            region_id="R000001",
            start=0x20000,
            end=0x21000,
            size=0x1000,
            permissions="rw-p",
            category="global",
            pathname="/tmp/sample",
            requested=0x1000,
            captured=0x1000,
            status="COMPLETE",
            filename="memory/region_global.bin"
        )

        self.reg_heap = CapturedRegion(
            region_id="R000002",
            start=0x5000,
            end=0x7000,
            size=0x2000,
            permissions="rw-p",
            category="heap",
            pathname="[heap]",
            requested=0x2000,
            captured=0x2000,
            status="COMPLETE",
            filename="memory/region_heap.bin"
        )

        self.raw_snap = RawMemorySnapshot(
            snapshot_id="M_OFFLINE_TEST",
            pid=9876,
            binary="/tmp/sample",
            timestamp_ns=123456789,
            output_dir=self.tmp_dir,
            regions=[self.reg_global, self.reg_heap],
            maps=[
                {"start_addr": 0x20000, "end_addr": 0x21000, "category": "global", "pathname": "/tmp/sample"},
                {"start_addr": 0x5000, "end_addr": 0x7000, "category": "heap", "pathname": "[heap]"},
            ]
        )

        # Synthetic DWARF symbol & type context
        self.symbol_context = {
            "symbols": [
                {"name": "global_session", "type": "Session *", "address": 0x18}
            ],
            "types": {
                "Session": {
                    "name": "Session",
                    "code": "aggregate",
                    "sizeof": 48,
                    "fields": [
                        {"name": "state", "type": "SessionState", "offset": 0, "sizeof": 4},
                        {"name": "retry", "type": "uint32_t", "offset": 4, "sizeof": 4},
                        {"name": "packet_count", "type": "uint32_t", "offset": 8, "sizeof": 4},
                        {"name": "buffer", "type": "Buffer *", "offset": 16, "sizeof": 8},
                        {"name": "parent", "type": "Session *", "offset": 24, "sizeof": 8},
                        {"name": "flagged", "type": "bool", "offset": 32, "sizeof": 1},
                        {"name": "priority", "type": "uint8_t", "offset": 33, "sizeof": 1},
                        {"name": "ratio", "type": "double", "offset": 40, "sizeof": 8},
                    ]
                },
                "Buffer": {
                    "name": "Buffer",
                    "code": "aggregate",
                    "sizeof": 16,
                    "fields": [
                        {"name": "length", "type": "uint32_t", "offset": 0, "sizeof": 4},
                        {"name": "capacity", "type": "uint32_t", "offset": 4, "sizeof": 4},
                        {"name": "data", "type": "char *", "offset": 8, "sizeof": 8},
                    ]
                },
                "SessionState": {
                    "name": "SessionState",
                    "code": "enum",
                    "sizeof": 4,
                    "fields": [
                        "SessionState::DISCONNECTED",
                        "SessionState::CONNECTED",
                        "SessionState::ERROR"
                    ]
                }
            }
        }

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_offline_analysis_and_semantic_graph(self):
        analyzer = OfflineMemoryAnalyzer()

        # Mock debug image provider
        class MockDebugImageProvider:
            path = "/tmp/sample.debug"
            def verify(self, runtime_binary):
                class Compat:
                    compatible = True
                    reason = "COMPATIBLE"
                return Compat()

        semantic_snap = analyzer.analyze(
            memory_snapshot=self.raw_snap,
            debug_image=MockDebugImageProvider(),
            optional_symbol_context=self.symbol_context
        )

        self.assertIsInstance(semantic_snap, RuntimeSnapshot)
        self.assertEqual(semantic_snap.snapshot_id, "S_M_OFFLINE_TEST")
        self.assertEqual(semantic_snap.process["capture_mode"], "LOW_IMPACT")

        # Verify persistent roots & objects
        persistent = semantic_snap.persistent
        self.assertEqual(len(persistent.roots), 1)
        root = persistent.roots[0]
        self.assertEqual(root.name, "global_session")
        self.assertEqual(root.address, "0x5000")
        self.assertIsNotNone(root.object_ref)

        # Discovered objects: Session and Buffer
        objects = {o.object_id: o for o in persistent.objects}
        self.assertEqual(len(objects), 2)

        session_obj = objects[root.object_ref]
        self.assertEqual(session_obj.type, "Session")
        self.assertEqual(session_obj.storage, "heap")

        fields = {f.name: f for f in session_obj.fields}
        self.assertEqual(fields["state"].value, "SessionState::CONNECTED")
        self.assertEqual(fields["retry"].value, 3)
        self.assertEqual(fields["packet_count"].value, 123)
        self.assertTrue(fields["flagged"].value)
        self.assertEqual(fields["priority"].value, 7)
        self.assertAlmostEqual(fields["ratio"].value, 2.5)

        # Verify circular reference: session->parent points back to session_obj
        self.assertEqual(fields["parent"].object_ref, session_obj.object_id)

        # Verify buffer object
        buffer_id = fields["buffer"].object_ref
        self.assertIsNotNone(buffer_id)
        buffer_obj = objects[buffer_id]
        self.assertEqual(buffer_obj.type, "Buffer")
        buf_fields = {f.name: f for f in buffer_obj.fields}
        self.assertEqual(buf_fields["length"].value, 64)
        self.assertEqual(buf_fields["capacity"].value, 256)

        # Compute semantic state hash
        h = compute_state_hash(semantic_snap)
        self.assertIsInstance(h, str)
        self.assertEqual(len(h), 16)


if __name__ == "__main__":
    unittest.main()
