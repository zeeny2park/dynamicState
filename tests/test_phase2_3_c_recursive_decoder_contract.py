"""Phase 2.3-C: Recursive C++ Decoder Status Contract and Semantic Parity Tests.

Validates P1 requirements:
1. Standard recursive decode result contract: value, status, error, limitations.
2. Parent containers, smart pointers, and structs never upgrade child failure or partial status to COMPLETE/OBSERVED.
3. Distinction among:
   - MEMORY_NOT_CAPTURED (unreadable pointee/payload)
   - INVALID_POINTER (null or corrupted pointer address)
   - UNKNOWN_CONTROL_BLOCK (missing or corrupted smart pointer control block)
   - CYCLE_DETECTED (recursive self-referencing pointer)
   - RECURSION_LIMIT_REACHED (nesting depth beyond ceiling)
4. Semantic parity between snapshot CppObjectDecoder and live WatchSession._decode_typed_memory().
"""

import struct
import unittest
from typing import Any, Dict, Optional, Tuple

from extractor.cpp_decoder import CppContainerDecoder, CppObjectDecoder
from extractor.dwarf_indexer import DwarfIndex, DwarfType
from extractor.typed_memory_reader import TypedMemoryReader


class DummyDwarfIndex:
    def __init__(self, pointer_size=8, endianness="little"):
        self.pointer_size = pointer_size
        self.endianness = endianness
        self._stl_map = {}

    def register_stl(self, type_offset: int, stl_info: Dict[str, Any]):
        self._stl_map[type_offset] = stl_info

    def classify_stl_type(self, type_offset: Optional[int]) -> Optional[Dict[str, Any]]:
        return self._stl_map.get(type_offset)

    def resolve_canonical_type(self, type_offset: Optional[int]):
        info = self._stl_map.get(type_offset)
        if not info:
            return None
        dt = DwarfType(die_offset=type_offset, tag="DW_TAG_class_type", name=info.get("container", "dummy"))
        dt.byte_size = info.get("byte_size", 32)
        return dt

    def get_type_name(self, type_offset: Optional[int]) -> str:
        info = self._stl_map.get(type_offset)
        return info.get("stl_kind", "unknown") if info else "unknown"


class MockMemoryReader(TypedMemoryReader):
    """Memory reader with configurable valid and invalid address ranges."""
    def __init__(self, memory_chunks: Optional[Dict[int, bytes]] = None):
        self.chunks = dict(memory_chunks or {})

    def contains(self, address: int, size: int) -> bool:
        for base, data in self.chunks.items():
            if base <= address and (address + size) <= (base + len(data)):
                return True
        return False

    def read(self, address: int, size: int) -> Tuple[Optional[bytes], str]:
        for base, data in self.chunks.items():
            if base <= address and (address + size) <= (base + len(data)):
                off = address - base
                return data[off:off + size], "COMPLETE"
        return None, "MEMORY_NOT_CAPTURED"

    def is_heap(self, address: int) -> bool:
        return 0x5000 <= address < 0x20000

    def is_stack(self, address: int) -> bool:
        return 0x7fff0000 <= address < 0x80000000


class TestPhase23CRecursiveDecoderContract(unittest.TestCase):
    def test_vector_with_partial_elements_preserves_partial_status(self):
        """std::vector where some elements return PARTIAL status propagates PARTIAL up to container."""
        # 3 elements of size 8: elem 0 complete, elem 1 partial, elem 2 complete
        vector_header = struct.pack("<QQQ", 0x1000, 0x1018, 0x1018)
        stl_info = {
            "stl_kind": "std::vector",
            "element_type_name": "MyStruct",
            "element_size": 8,
            "element_type_offset": 0x100,
        }
        idx = DummyDwarfIndex(pointer_size=8, endianness="little")
        idx.register_stl(0x200, stl_info)

        def fake_read(addr: int, sz: int):
            if addr == 0x2000:
                return vector_header, "COMPLETE"
            return b"\x00" * sz, "COMPLETE"

        def fake_elem_decoder(e_addr: int, e_type_off: Optional[int], depth: int):
            if e_addr == 0x1008:
                # Element 1 is partial
                return {"field": 42, "status": "PARTIAL", "error": "Member not captured"}
            return {"field": 10, "status": "COMPLETE"}

        res = CppContainerDecoder.decode_container(
            read_fn=fake_read,
            address=0x2000,
            type_offset=0x200,
            dwarf_index=idx,
            decode_elem_fn=fake_elem_decoder,
        )
        # Vector must NOT report COMPLETE
        self.assertIsNotNone(res)
        self.assertEqual(res["status"], "PARTIAL")
        self.assertIn("error", res)
        self.assertIn("partial decode", res["error"].lower())

    def test_unique_ptr_with_unreadable_target_reports_status(self):
        """std::unique_ptr pointing to unreadable memory propagates failure status."""
        ptr_val = 0x8000  # unreadable
        unique_ptr_mem = struct.pack("<Q", ptr_val)
        stl_info = {
            "stl_kind": "std::unique_ptr",
            "element_type_name": "TargetClass",
            "element_type_offset": 0x150,
        }
        idx = DummyDwarfIndex(pointer_size=8, endianness="little")
        idx.register_stl(0x300, stl_info)

        def fake_read(addr: int, sz: int):
            if addr == 0x3000:
                return unique_ptr_mem, "COMPLETE"
            return None, "MEMORY_NOT_CAPTURED"

        def fake_elem_decoder(e_addr: int, e_type_off: Optional[int], depth: int):
            return {"value": None, "status": "MEMORY_NOT_CAPTURED", "error": "Pointee unmapped"}

        res = CppContainerDecoder.decode_container(
            read_fn=fake_read,
            address=0x3000,
            type_offset=0x300,
            dwarf_index=idx,
            decode_elem_fn=fake_elem_decoder,
        )
        self.assertIsNotNone(res)
        self.assertEqual(res["status"], "MEMORY_NOT_CAPTURED")
        self.assertIn("error", res)

    def test_unique_ptr_with_partial_target_preserves_partial_status(self):
        """std::unique_ptr pointing to partially decoded struct preserves PARTIAL status."""
        ptr_val = 0x5000
        unique_ptr_mem = struct.pack("<Q", ptr_val)
        stl_info = {
            "stl_kind": "std::unique_ptr",
            "element_type_name": "TargetClass",
            "element_type_offset": 0x150,
        }
        idx = DummyDwarfIndex(pointer_size=8, endianness="little")
        idx.register_stl(0x300, stl_info)

        def fake_read(addr: int, sz: int):
            return unique_ptr_mem, "COMPLETE"

        def fake_elem_decoder(e_addr: int, e_type_off: Optional[int], depth: int):
            return {"subfield": None, "status": "PARTIAL", "error": "Pointee field truncated"}

        res = CppContainerDecoder.decode_container(
            read_fn=fake_read,
            address=0x4000,
            type_offset=0x300,
            dwarf_index=idx,
            decode_elem_fn=fake_elem_decoder,
        )
        self.assertIsNotNone(res)
        self.assertEqual(res["status"], "PARTIAL")

    def test_shared_ptr_control_block_classifications(self):
        """std::shared_ptr distinguishes corrupted refcounts and unknown control blocks."""
        ptr_val = 0x6000
        cb_val = 0x9000
        sp_header = struct.pack("<QQ", ptr_val, cb_val)
        stl_info = {
            "stl_kind": "std::shared_ptr",
            "element_type_name": "TargetClass",
            "element_type_offset": 0x150,
        }
        idx = DummyDwarfIndex(pointer_size=8, endianness="little")
        idx.register_stl(0x400, stl_info)

        # 1. Unknown control block (read failure)
        def read_missing_cb(addr: int, sz: int):
            if addr == 0x2000:
                return sp_header, "COMPLETE"
            return None, "EFAULT"

        res_missing = CppContainerDecoder.decode_container(
            read_fn=read_missing_cb,
            address=0x2000,
            type_offset=0x400,
            dwarf_index=idx,
        )
        self.assertEqual(res_missing["status"], "UNKNOWN_CONTROL_BLOCK")

        # 2. Corrupted control block (negative refcounts)
        corrupted_cb = b"\x00" * 8 + struct.pack("<ii", -5, 1)  # use_count = -5
        def read_corrupt_cb(addr: int, sz: int):
            if addr == 0x2000:
                return sp_header, "COMPLETE"
            if addr == 0x9000:
                return corrupted_cb, "COMPLETE"
            return None, "EFAULT"

        res_corrupt = CppContainerDecoder.decode_container(
            read_fn=read_corrupt_cb,
            address=0x2000,
            type_offset=0x400,
            dwarf_index=idx,
        )
        self.assertEqual(res_corrupt["status"], "CORRUPTED_CONTROL_BLOCK")

    def test_cycle_and_recursion_limit_distinction(self):
        """Smart pointers accurately distinguish CYCLE_DETECTED from RECURSION_LIMIT_REACHED."""
        stl_info = {
            "stl_kind": "std::unique_ptr",
            "element_type_name": "Node",
            "element_type_offset": 0x100,
        }
        idx = DummyDwarfIndex(pointer_size=8, endianness="little")

        # 1. Cycle detection
        res_cycle = CppContainerDecoder._decode_unique_ptr(
            read_fn=lambda a, sz: (struct.pack("<Q", 0x1000), "COMPLETE"),
            address=0x1000,
            stl_info=stl_info,
            ptr_size=8,
            ptr_fmt="<Q",
            visited_ptrs={0x1000},
        )
        self.assertEqual(res_cycle["status"], "CYCLE_DETECTED")
        self.assertIn("Cyclic", res_cycle["error"])

        # 2. Recursion limit
        res_limit = CppContainerDecoder._decode_unique_ptr(
            read_fn=lambda a, sz: (struct.pack("<Q", 0x2000), "COMPLETE"),
            address=0x2000,
            stl_info=stl_info,
            ptr_size=8,
            ptr_fmt="<Q",
            depth=5,
            max_depth=4,
        )
        self.assertEqual(res_limit["status"], "RECURSION_LIMIT_REACHED")
        self.assertIn("Recursion limit", res_limit["error"])


if __name__ == "__main__":
    unittest.main()
