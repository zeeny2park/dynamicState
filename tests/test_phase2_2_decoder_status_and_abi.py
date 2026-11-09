"""Tests for Phase 2.2-C-A: C++ Decoder Status and ABI Correctness.

Verifies:
1. std::string ABI validation, short header reads, SSO corruption, heap corruption,
   partial/missing payload reads (never defaulting to ""), and status propagation.
2. std::vector divisibility checking, boundary corruption, invalid pointers,
   element failure propagation, and max_elements truncation vs read failure.
3. Smart pointer ownership, null/invalid pointer handling, control block validation,
   and recursion/cycle detection.
4. WatchSession._decode_typed_memory() end-to-end status propagation without masking.
"""

import tempfile
import struct
import unittest
from typing import Optional, Tuple, Dict, Any

from extractor.cpp_decoder import CppContainerDecoder
from extractor.dwarf_indexer import DwarfIndex, DwarfType
from extractor.watch_session import WatchSessionManager
from extractor.target_adapter import TargetExecutionAdapter


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


class MockTargetAdapter(TargetExecutionAdapter):
    def __init__(self, mem_map: Optional[Dict[int, bytes]] = None):
        self.mem_map = mem_map or {}

    def read_memory(self, pid: int, address: int, size: int) -> Tuple[Optional[bytes], str, Optional[str]]:
        if address in self.mem_map:
            data = self.mem_map[address]
            if len(data) >= size:
                return data[:size], "OBSERVED", None
            return data, "PARTIAL", f"Short read: got {len(data)}, expected {size}"
        return None, "UNMAPPED", f"Address 0x{address:x} is unmapped"

    def is_process_alive(self, pid: int) -> bool:
        return True

    def check_liveness(self, pid: int) -> bool:
        return True

    def get_process_identity(self, pid: int):
        return None

    def get_proc_maps(self, pid: int):
        return []

    def get_threads(self, pid: int):
        return []

    def is_remote(self) -> bool:
        return False

    def target_host(self) -> str:
        return "localhost"

    def write_memory(self, pid: int, address: int, data: bytes) -> Tuple[bool, str]:
        return False, "Not implemented"

    def execute_command(self, cmd: str) -> Tuple[int, str, str]:
        return 0, "", ""


class TestCppDecoderStatusAndABI(unittest.TestCase):
    def setUp(self):
        self.idx = DummyDwarfIndex(pointer_size=8, endianness="little")

    # --- std::string tests ---
    def test_string_unsupported_abi(self):
        """String with ABI size != 32 on 64-bit must report UNSUPPORTED_ABI."""
        self.idx.register_stl(100, {
            "stl_kind": "std::string",
            "element_type_name": "char",
            "byte_size": 24,  # libc++ or non-standard size
        })
        def reader(addr, sz):
            return b"\x00" * sz, "OBSERVED"

        res = CppContainerDecoder.decode_container(
            read_fn=reader,
            address=0x1000,
            type_offset=100,
            dwarf_index=self.idx,
        )
        self.assertEqual(res["status"], "UNSUPPORTED_ABI")
        self.assertIsNone(res["value"])
        self.assertIn("Unsupported std::string ABI layout", res["error"])

    def test_string_short_header_read(self):
        """Header read returning fewer than 32 bytes reports SHORT_READ."""
        self.idx.register_stl(101, {
            "stl_kind": "std::string",
            "element_type_name": "char",
            "byte_size": 32,
        })
        def reader(addr, sz):
            return b"short_header", "PARTIAL"

        res = CppContainerDecoder.decode_container(
            read_fn=reader,
            address=0x1000,
            type_offset=101,
            dwarf_index=self.idx,
        )
        self.assertEqual(res["status"], "SHORT_READ")
        self.assertIsNone(res["value"])

    def test_string_sso_corrupted_length(self):
        """SSO string whose length exceeds SSO capacity (15) reports CORRUPTED_BOUNDARIES."""
        self.idx.register_stl(102, {
            "stl_kind": "std::string",
            "element_type_name": "char",
            "byte_size": 32,
        })
        # data_ptr = addr + 16 (SSO buffer), length = 20 (> 15)
        raw_header = struct.pack("<QQ16s", 0x1000 + 16, 20, b"abcdefghijklmnop")
        def reader(addr, sz):
            return raw_header, "OBSERVED"

        res = CppContainerDecoder.decode_container(
            read_fn=reader,
            address=0x1000,
            type_offset=102,
            dwarf_index=self.idx,
        )
        self.assertEqual(res["status"], "CORRUPTED_BOUNDARIES")
        self.assertIsNone(res["value"])
        self.assertIn("SSO length 20 exceeds SSO capacity 15", res["error"])

    def test_string_heap_missing_payload_never_returns_empty(self):
        """Heap string whose payload cannot be read must return MEMORY_NOT_CAPTURED and None, NOT empty string."""
        self.idx.register_stl(103, {
            "stl_kind": "std::string",
            "element_type_name": "char",
            "byte_size": 32,
        })
        # Heap string pointing to 0x5000 with length 10, capacity 16
        raw_header = struct.pack("<QQQ8s", 0x5000, 10, 16, b"")
        def reader(addr, sz):
            if addr == 0x1000:
                return raw_header, "OBSERVED"
            # Payload read fails (unmapped)
            return None, "UNMAPPED"

        res = CppContainerDecoder.decode_container(
            read_fn=reader,
            address=0x1000,
            type_offset=103,
            dwarf_index=self.idx,
        )
        self.assertEqual(res["status"], "MEMORY_NOT_CAPTURED")
        self.assertIsNone(res["value"])  # Must NOT be ""!
        self.assertIsNotNone(res.get("error"))

    def test_string_heap_partial_payload_read(self):
        """Heap string whose payload read is partial reports PARTIAL with partial data."""
        self.idx.register_stl(104, {
            "stl_kind": "std::string",
            "element_type_name": "char",
            "byte_size": 32,
        })
        raw_header = struct.pack("<QQQ8s", 0x5000, 12, 16, b"")
        def reader(addr, sz):
            if addr == 0x1000:
                return raw_header, "OBSERVED"
            if addr == 0x5000:
                # Expected 12 bytes, got only 4
                return b"Part", "PARTIAL"
            return None, "UNMAPPED"

        res = CppContainerDecoder.decode_container(
            read_fn=reader,
            address=0x1000,
            type_offset=104,
            dwarf_index=self.idx,
        )
        self.assertEqual(res["status"], "PARTIAL")
        self.assertEqual(res["value"], "Part")
        self.assertIn("Partial payload read (4/12 bytes)", res["error"])

    # --- std::vector tests ---
    def test_vector_non_divisible_byte_length(self):
        """Vector whose finish - start is not divisible by element_size reports NON_DIVISIBLE_BYTE_LENGTH."""
        self.idx.register_stl(200, {
            "stl_kind": "std::vector",
            "element_type_name": "int",
            "element_size": 4,
            "byte_size": 24,
        })
        # start=0x2000, finish=0x2005 (5 bytes, not divisible by 4), cap=0x2010 (16 bytes)
        raw_header = struct.pack("<QQQ", 0x2000, 0x2005, 0x2010)
        def reader(addr, sz):
            return raw_header, "OBSERVED"

        res = CppContainerDecoder.decode_container(
            read_fn=reader,
            address=0x1000,
            type_offset=200,
            dwarf_index=self.idx,
        )
        self.assertEqual(res["status"], "NON_DIVISIBLE_BYTE_LENGTH")
        self.assertIn("not divisible by element size 4", res["error"])

    def test_vector_corrupted_capacity_divisibility(self):
        """Vector whose end_of_storage - start is not divisible by element_size reports CORRUPTED_BOUNDARIES."""
        self.idx.register_stl(201, {
            "stl_kind": "std::vector",
            "element_type_name": "int",
            "element_size": 4,
            "byte_size": 24,
        })
        # start=0x2000, finish=0x2008 (8 bytes), cap=0x200b (11 bytes, not divisible by 4)
        raw_header = struct.pack("<QQQ", 0x2000, 0x2008, 0x200b)
        def reader(addr, sz):
            return raw_header, "OBSERVED"

        res = CppContainerDecoder.decode_container(
            read_fn=reader,
            address=0x1000,
            type_offset=201,
            dwarf_index=self.idx,
        )
        self.assertEqual(res["status"], "CORRUPTED_BOUNDARIES")

    def test_vector_element_failures_partial_and_failed(self):
        """Vector whose elements fail to decode propagates PARTIAL or ELEMENT_READ_FAILED."""
        self.idx.register_stl(202, {
            "stl_kind": "std::vector",
            "element_type_name": "int",
            "element_size": 4,
            "byte_size": 24,
        })
        # 3 elements (12 bytes)
        raw_header = struct.pack("<QQQ", 0x2000, 0x200c, 0x2010)
        def reader(addr, sz):
            return raw_header, "OBSERVED"

        # Mock element decoder where element 1 succeeds, element 2 fails
        def elem_decoder(addr, type_off, depth):
            if addr == 0x2000:
                return 42
            return None  # Failed read

        res = CppContainerDecoder.decode_container(
            read_fn=reader,
            address=0x1000,
            type_offset=202,
            dwarf_index=self.idx,
            decode_elem_fn=elem_decoder,
        )
        self.assertEqual(res["status"], "PARTIAL")
        self.assertEqual(len(res["elements"]), 3)
        self.assertIn("Failed to read 2 of 3 decoded elements", res["error"])

    # --- Smart Pointer tests ---
    def test_unique_ptr_cycle_detection(self):
        """Smart pointers pointing recursively must detect cycle."""
        self.idx.register_stl(300, {
            "stl_kind": "std::unique_ptr",
            "element_type_name": "Node",
            "byte_size": 8,
        })
        visited = {0x1000}
        def reader(addr, sz):
            return struct.pack("<Q", 0x1000), "OBSERVED"

        res = CppContainerDecoder.decode_container(
            read_fn=reader,
            address=0x1000,
            type_offset=300,
            dwarf_index=self.idx,
            visited_ptrs=visited,
        )
        self.assertEqual(res["status"], "CYCLE_DETECTED")
        self.assertIn("Cyclic pointer reference", res["error"])

    def test_shared_ptr_unreadable_control_block(self):
        """shared_ptr whose control block memory cannot be captured reports UNKNOWN_CONTROL_BLOCK."""
        self.idx.register_stl(400, {
            "stl_kind": "std::shared_ptr",
            "element_type_name": "int",
            "byte_size": 16,
        })
        # target=0x3000, cb=0x4000
        raw_header = struct.pack("<QQ", 0x3000, 0x4000)
        def reader(addr, sz):
            if addr == 0x1000:
                return raw_header, "OBSERVED"
            return None, "UNMAPPED"  # control block unmapped

        res = CppContainerDecoder.decode_container(
            read_fn=reader,
            address=0x1000,
            type_offset=400,
            dwarf_index=self.idx,
        )
        self.assertEqual(res["status"], "UNKNOWN_CONTROL_BLOCK")
        self.assertIn("Failed to read control block", res["error"])

    # --- WatchSession status propagation tests ---
    def test_watch_session_propagates_decoder_errors(self):
        """WatchSession._decode_typed_memory must return actual decoder status rather than OBSERVED."""
        td = tempfile.mkdtemp()
        session = WatchSessionManager(td)
        self.idx.register_stl(103, {
            "stl_kind": "std::string",
            "element_type_name": "char",
            "byte_size": 32,
        })
        # Header points to unmapped 0x5000
        raw_header = struct.pack("<QQQ8s", 0x5000, 10, 16, b"")
        mem_map = {0x1000: raw_header}
        adapter = MockTargetAdapter(mem_map)

        val, status, err, raw_hex = session._decode_typed_memory(
            adapter=adapter,
            pid=1234,
            idx=self.idx,
            addr=0x1000,
            type_offset=103,
        )
        # Must report MEMORY_NOT_CAPTURED, not OBSERVED!
        self.assertEqual(status, "MEMORY_NOT_CAPTURED")
        self.assertIsNone(val)
        self.assertIsNotNone(err)


if __name__ == "__main__":
    unittest.main()
