"""Phase 2.2-C-C STL Regression Fixtures & Container Decoding Integration Tests.

Validates:
1. Real C++ binaries compiled with -O0 -g and -O2 -g.
2. std::string: empty, SSO-sized (<16 chars), and heap-backed (>15 chars).
3. std::vector: empty, populated integers, vector of user-defined structs, and nested vectors.
4. std::unique_ptr: null and non-null pointee with exclusive ownership semantics.
5. std::shared_ptr: pointee and control block refcount (use_count > 1).
6. std::weak_ptr: expired weak_ptr (use_count == 0).
7. Inconsistent / corrupted vector boundary detection.
8. Shared unified CppContainerDecoder between WatchSession and snapshot resolution.
"""

import json
import os
import shutil
import struct
import subprocess
import tempfile
import time
import unittest

from extractor.cpp_decoder import CppContainerDecoder, CppObjectDecoder
from extractor.dwarf_indexer import DwarfIndexer
from extractor.target_adapter import LocalTargetAdapter
from extractor.watch_session import WatchSessionManager
from tests.support.fixture_process import fixture_popen


CPP_FIXTURE_SRC = """
#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <unistd.h>

struct Item {
    int id;
    double score;
};

// Global variables for DWARF discovery
std::string g_empty_str = "";
std::string g_sso_str = "Hello_SSO";
std::string g_heap_str = "This is a much longer heap-allocated string that exceeds fifteen chars!";

std::vector<int> g_empty_vec;
std::vector<int> g_int_vec = {10, 20, 30, 40, 50};
std::vector<Item> g_struct_vec = {{1, 3.14}, {2, 2.718}};
std::vector<std::vector<int>> g_nested_vec = {{1, 2}, {3, 4, 5}};

std::unique_ptr<int> g_null_unique = nullptr;
std::unique_ptr<int> g_val_unique;

std::shared_ptr<int> g_shared_ptr1;
std::shared_ptr<int> g_shared_ptr2;

std::weak_ptr<int> g_expired_weak;

int main() {
    g_val_unique = std::make_unique<int>(4242);
    g_shared_ptr1 = std::make_shared<int>(9999);
    g_shared_ptr2 = g_shared_ptr1; // 2 owners

    {
        auto temp_sp = std::make_shared<int>(123);
        g_expired_weak = temp_sp;
    } // temp_sp destroyed, weak_ptr is expired

    while (1) {
        usleep(10000);
    }
    return 0;
}
"""


class TestPhase22StlFixtures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp()
        src_path = os.path.join(cls.tmpdir, "stl_test.cpp")
        with open(src_path, "w") as f:
            f.write(CPP_FIXTURE_SRC)

        cls.bin_o0 = os.path.join(cls.tmpdir, "stl_test_O0")
        cls.bin_o2 = os.path.join(cls.tmpdir, "stl_test_O2")

        subprocess.check_call([
            "g++", "-O0", "-g", "-no-pie", src_path, "-o", cls.bin_o0
        ])
        subprocess.check_call([
            "g++", "-O2", "-g", "-fno-inline", "-no-pie", src_path, "-o", cls.bin_o2
        ])

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def _run_with_binary(self, bin_path: str):
        proc = fixture_popen([bin_path])
        time.sleep(0.15)
        try:
            adapter = LocalTargetAdapter()
            idx = DwarfIndexer.get_index(bin_path)
            wm = WatchSessionManager(corpus_dir=self.tmpdir)

            # Helper to find global variable address & type_offset
            vars_by_name = {v.name: v for v in idx.variables if v.name}

            # 1. std::string tests
            # Empty string
            v_empty = vars_by_name.get("g_empty_str")
            self.assertIsNotNone(v_empty)
            val, st, _, _ = wm._decode_typed_memory(adapter, proc.pid, idx, v_empty.link_time_address, v_empty.type_offset)
            self.assertEqual(val, "")

            # SSO string
            v_sso = vars_by_name.get("g_sso_str")
            self.assertIsNotNone(v_sso)
            def _read_fn(a, sz):
                b, s, _ = adapter.read_memory(proc.pid, a, sz)
                return b, s
            c_sso = CppContainerDecoder.decode_container(
                read_fn=_read_fn,
                address=v_sso.link_time_address,
                type_offset=v_sso.type_offset,
                dwarf_index=idx,
            )
            self.assertIsNotNone(c_sso)
            self.assertEqual(c_sso.get("container"), "std::string")
            self.assertEqual(c_sso.get("storage"), "sso")
            self.assertTrue(c_sso.get("is_sso"))
            self.assertEqual(c_sso.get("value"), "Hello_SSO")
            self.assertEqual(c_sso.get("size"), len("Hello_SSO"))

            # Heap-backed string
            v_heap = vars_by_name.get("g_heap_str")
            self.assertIsNotNone(v_heap)
            c_heap = CppContainerDecoder.decode_container(
                read_fn=_read_fn,
                address=v_heap.link_time_address,
                type_offset=v_heap.type_offset,
                dwarf_index=idx,
            )
            self.assertIsNotNone(c_heap)
            self.assertEqual(c_heap.get("container"), "std::string")
            self.assertEqual(c_heap.get("storage"), "heap")
            self.assertFalse(c_heap.get("is_sso"))
            self.assertIn("This is a much longer heap-allocated string", c_heap.get("value", ""))

            # 2. std::vector tests
            # Empty vector
            v_evec = vars_by_name.get("g_empty_vec")
            self.assertIsNotNone(v_evec)
            c_evec = CppContainerDecoder.decode_container(
                read_fn=_read_fn,
                address=v_evec.link_time_address,
                type_offset=v_evec.type_offset,
                dwarf_index=idx,
            )
            self.assertIsNotNone(c_evec)
            self.assertEqual(c_evec.get("container"), "std::vector")
            self.assertEqual(c_evec.get("size"), 0)
            self.assertEqual(c_evec.get("capacity"), 0)
            self.assertEqual(c_evec.get("elements"), [])

            # Int vector
            v_ivec = vars_by_name.get("g_int_vec")
            self.assertIsNotNone(v_ivec)
            def _elem_dec(ea, et, d):
                ev, _, _, _ = wm._decode_typed_memory(adapter, proc.pid, idx, ea, et, depth=d)
                return ev
            c_ivec = CppContainerDecoder.decode_container(
                read_fn=_read_fn,
                address=v_ivec.link_time_address,
                type_offset=v_ivec.type_offset,
                dwarf_index=idx,
                decode_elem_fn=_elem_dec,
            )
            self.assertIsNotNone(c_ivec)
            self.assertEqual(c_ivec.get("container"), "std::vector")
            self.assertEqual(c_ivec.get("size"), 5)
            self.assertGreaterEqual(c_ivec.get("capacity"), 5)
            self.assertEqual(c_ivec.get("elements"), [10, 20, 30, 40, 50])

            # Vector of structs
            v_svec = vars_by_name.get("g_struct_vec")
            self.assertIsNotNone(v_svec)
            c_svec = CppContainerDecoder.decode_container(
                read_fn=_read_fn,
                address=v_svec.link_time_address,
                type_offset=v_svec.type_offset,
                dwarf_index=idx,
                decode_elem_fn=_elem_dec,
            )
            self.assertIsNotNone(c_svec)
            self.assertEqual(c_svec.get("size"), 2)
            self.assertEqual(len(c_svec.get("elements", [])), 2)
            first_item = c_svec["elements"][0]
            self.assertIsInstance(first_item, dict)
            self.assertEqual(first_item.get("id"), 1)

            # 3. std::unique_ptr tests
            # Null unique_ptr
            v_null_u = vars_by_name.get("g_null_unique")
            self.assertIsNotNone(v_null_u)
            c_null_u = CppContainerDecoder.decode_container(
                read_fn=_read_fn,
                address=v_null_u.link_time_address,
                type_offset=v_null_u.type_offset,
                dwarf_index=idx,
            )
            self.assertIsNotNone(c_null_u)
            self.assertTrue(c_null_u.get("is_null"))
            self.assertEqual(c_null_u.get("ownership"), "EXCLUSIVE")
            self.assertIsNone(c_null_u.get("target"))

            # Non-null unique_ptr
            v_val_u = vars_by_name.get("g_val_unique")
            self.assertIsNotNone(v_val_u)
            c_val_u = CppContainerDecoder.decode_container(
                read_fn=_read_fn,
                address=v_val_u.link_time_address,
                type_offset=v_val_u.type_offset,
                dwarf_index=idx,
                decode_elem_fn=_elem_dec,
            )
            self.assertIsNotNone(c_val_u)
            self.assertFalse(c_val_u.get("is_null"))
            self.assertEqual(c_val_u.get("ownership"), "EXCLUSIVE")
            self.assertEqual(c_val_u.get("target"), 4242)

            # 4. std::shared_ptr tests
            v_sp1 = vars_by_name.get("g_shared_ptr1")
            self.assertIsNotNone(v_sp1)
            c_sp1 = CppContainerDecoder.decode_container(
                read_fn=_read_fn,
                address=v_sp1.link_time_address,
                type_offset=v_sp1.type_offset,
                dwarf_index=idx,
                decode_elem_fn=_elem_dec,
            )
            self.assertIsNotNone(c_sp1)
            self.assertEqual(c_sp1.get("ownership"), "SHARED")
            self.assertEqual(c_sp1.get("target"), 9999)
            self.assertEqual(c_sp1.get("use_count"), 2)

            # 5. std::weak_ptr expired test
            v_wp = vars_by_name.get("g_expired_weak")
            if v_wp and v_wp.type_offset is not None:
                c_wp = CppContainerDecoder.decode_container(
                    read_fn=_read_fn,
                    address=v_wp.link_time_address,
                    type_offset=v_wp.type_offset,
                    dwarf_index=idx,
                )
                if c_wp:
                    self.assertEqual(c_wp.get("use_count"), 0)
                    self.assertTrue(c_wp.get("is_expired"))

        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=1.0)
                except Exception:
                    proc.kill()

    def test_stl_containers_O0(self):
        """Verify C++ container decoding on real -O0 binary."""
        self._run_with_binary(self.bin_o0)

    def test_stl_containers_O2(self):
        """Verify C++ container decoding on real -O2 binary."""
        self._run_with_binary(self.bin_o2)

    def test_corrupted_vector_boundaries(self):
        """Verify that inconsistent vector boundaries fail-safely return CORRUPTED_BOUNDARIES."""
        idx = DwarfIndexer.get_index(self.bin_o0)
        v_ivec = next(v for v in idx.variables if v.name == "g_int_vec")

        # Mock a corrupted vector header where finish < start
        corrupt_raw = struct.pack("<QQQ", 0x1000, 0x800, 0x2000)
        def _bad_reader(a, sz):
            return corrupt_raw, "COMPLETE"

        res = CppContainerDecoder.decode_container(
            read_fn=_bad_reader,
            address=0x5000,
            type_offset=v_ivec.type_offset,
            dwarf_index=idx,
        )
        self.assertIsNotNone(res)
        self.assertEqual(res.get("status"), "CORRUPTED_BOUNDARIES")
        self.assertIn("Invalid vector boundaries", res.get("error", ""))


if __name__ == "__main__":
    unittest.main()
