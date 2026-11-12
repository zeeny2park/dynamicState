"""
tests/test_phase2_2_resilient_capture.py

Tests for Phase 2.2-B: Resilient Memory Capture (GAP-P0-02).

Verifies:
1. Multi-page chunk with guard page in the middle:
   - Readable pages before and after the guard page are salvaged.
   - Guard page is excluded from buffers and captured_ranges.
   - Exact byte ranges preserved.
   - Zero false zero-bytes returned for the guard page.
2. Multi-page chunk with leading guard page:
   - Initial EFAULT does not cause the entire chunk to be dropped.
   - Trailing readable pages are salvaged.
3. Completely unreadable chunk is marked FAILED without crashing.
"""

import errno
import mmap
import os
import unittest

from extractor.capture_backend import (
    CaptureMode,
    CapturePlan,
    CaptureSafetyPolicy,
    ProcessTargetHandle,
    ProcessVmCaptureBackend,
)
from tests.test_capture_lifecycle_seam import MockProcessTargetAdapter


class TestPhase22ResilientCapture(unittest.TestCase):
    """Phase 2.2-B Resilient Memory Capture Test Suite."""

    def test_middle_guard_page_resilience_with_mem_reader(self):
        """A 3-page chunk with page 1 failing due to EFAULT salvages page 0 and page 2."""
        backend = ProcessVmCaptureBackend()
        pid = os.getpid()

        page_size = 4096
        reg_start = 0x10000000
        reg_size = 3 * page_size  # 3 pages: 0x10000000, 0x10001000, 0x10002000

        page0_data = b"A" * page_size
        page2_data = b"C" * page_size

        def mock_mem_reader(target_pid, addr, size):
            # If full chunk requested (12KB), it hits page 1 and fails with EFAULT
            if size > page_size:
                return None  # EFAULT simulated
            if addr == reg_start:
                return page0_data
            elif addr == reg_start + page_size:
                return None  # Guard page (EFAULT)
            elif addr == reg_start + 2 * page_size:
                return page2_data
            return None

        adapter = MockProcessTargetAdapter(pid=pid, initial_state="STOPPED")
        handle = ProcessTargetHandle(pid=pid, adapter=adapter)
        policy = CaptureSafetyPolicy(
            target_handle=handle,
            max_capture_bytes=1024 * 1024,
            mem_reader=mock_mem_reader,
        )
        plan = CapturePlan(
            mode=CaptureMode.TARGETED.value, allow_stop=True,
            memory_ranges=[(reg_start, reg_start + reg_size)],
        )

        snapshot = backend.capture(pid=pid, plan=plan, policy=policy)

        # 1. Chunk was NOT dropped completely
        self.assertGreater(snapshot.provenance["bytes_read"], 0)
        self.assertEqual(snapshot.provenance["bytes_read"], 2 * page_size)

        # 2. Page 0 and Page 2 are in captured_ranges
        captured = snapshot.captured_ranges
        self.assertIn((reg_start, reg_start + page_size), captured)
        self.assertIn((reg_start + 2 * page_size, reg_start + 3 * page_size), captured)
        self.assertNotIn((reg_start + page_size, reg_start + 2 * page_size), captured)

        # 3. Exact bytes preserved
        self.assertEqual(snapshot.read_bytes(reg_start, 100), b"A" * 100)
        self.assertEqual(snapshot.read_bytes(reg_start + 2 * page_size, 100), b"C" * 100)

        # 4. Failed guard page returns None (zero false zeros)
        self.assertIsNone(snapshot.read_bytes(reg_start + page_size, 100))
        self.assertIsNone(snapshot.read_bytes(reg_start + page_size + 2048, 8))

        # 5. Region status is PARTIAL with unreadable subranges accurately recorded
        reg_meta = snapshot.memory_regions[0]
        self.assertEqual(reg_meta["status"], "PARTIAL")
        self.assertEqual(reg_meta["captured_bytes"], 2 * page_size)
        self.assertIn("unreadable_subranges", reg_meta)
        self.assertEqual(len(reg_meta["unreadable_subranges"]), 1)
        expected_unreadable = [f"0x{reg_start + page_size:x}", f"0x{reg_start + 2 * page_size:x}"]
        self.assertEqual(reg_meta["unreadable_subranges"][0], expected_unreadable)

    def test_leading_guard_page_resilience(self):
        """A 3-page chunk with leading guard page (page 0 EFAULT) salvages pages 1 and 2."""
        backend = ProcessVmCaptureBackend()
        pid = os.getpid()

        page_size = 4096
        reg_start = 0x20000000
        reg_size = 3 * page_size

        page1_data = b"X" * page_size
        page2_data = b"Y" * page_size

        def mock_mem_reader(target_pid, addr, size):
            if size > page_size:
                return None  # Leading page causes EFAULT on full read
            if addr == reg_start:
                return None  # Leading guard page
            elif addr == reg_start + page_size:
                return page1_data
            elif addr == reg_start + 2 * page_size:
                return page2_data
            return None

        adapter = MockProcessTargetAdapter(pid=pid, initial_state="STOPPED")
        handle = ProcessTargetHandle(pid=pid, adapter=adapter)
        policy = CaptureSafetyPolicy(
            target_handle=handle,
            max_capture_bytes=1024 * 1024,
            mem_reader=mock_mem_reader,
        )
        plan = CapturePlan(
            mode=CaptureMode.TARGETED.value, allow_stop=True,
            memory_ranges=[(reg_start, reg_start + reg_size)],
        )

        snapshot = backend.capture(pid=pid, plan=plan, policy=policy)

        self.assertEqual(snapshot.provenance["bytes_read"], 2 * page_size)
        self.assertIn((reg_start + page_size, reg_start + 3 * page_size), snapshot.captured_ranges)
        self.assertIsNone(snapshot.read_bytes(reg_start, 64))
        self.assertEqual(snapshot.read_bytes(reg_start + page_size, 64), b"X" * 64)
        self.assertEqual(snapshot.read_bytes(reg_start + 2 * page_size, 64), b"Y" * 64)

    def test_all_pages_failed_marks_region_failed(self):
        """A multi-page chunk where all pages fail with EFAULT cleanly marks region FAILED."""
        backend = ProcessVmCaptureBackend()
        pid = os.getpid()

        page_size = 4096
        reg_start = 0x30000000
        reg_size = 2 * page_size

        def mock_mem_reader(target_pid, addr, size):
            return None  # All pages fail

        adapter = MockProcessTargetAdapter(pid=pid, initial_state="STOPPED")
        handle = ProcessTargetHandle(pid=pid, adapter=adapter)
        policy = CaptureSafetyPolicy(
            target_handle=handle,
            max_capture_bytes=1024 * 1024,
            mem_reader=mock_mem_reader,
        )
        plan = CapturePlan(
            mode=CaptureMode.TARGETED.value, allow_stop=True,
            memory_ranges=[(reg_start, reg_start + reg_size)],
        )

        snapshot = backend.capture(pid=pid, plan=plan, policy=policy)

        self.assertEqual(snapshot.provenance["bytes_read"], 0)
        self.assertEqual(len(snapshot.captured_ranges), 0)
        self.assertEqual(snapshot.memory_regions[0]["status"], "FAILED")
        self.assertEqual(snapshot.memory_regions[0]["captured_bytes"], 0)

    def test_real_inferior_guard_page_process_vm_readv(self):
        """Authentic Linux process with PROT_NONE guard page: process_vm_readv salvages valid pages."""
        import subprocess
        import sys

        # Spawn a python child process that creates 3 mapped pages: [RW, PROT_NONE, RW]
        child_code = """
import mmap, sys, time, ctypes

libc = ctypes.CDLL(None)
mprotect = libc.mprotect
mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
mprotect.restype = ctypes.c_int

PROT_NONE = 0
PROT_READ = 1
PROT_WRITE = 2

page_size = 4096
total_size = 3 * page_size

mm = mmap.mmap(-1, total_size, mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS, mmap.PROT_READ | mmap.PROT_WRITE)
addr = ctypes.addressof(ctypes.c_char.from_buffer(mm))

# Write markers
ctypes.memmove(addr, b"PAGE0_MARKER" + b"X" * (page_size - 12), page_size)
ctypes.memmove(addr + 2 * page_size, b"PAGE2_MARKER" + b"Y" * (page_size - 12), page_size)

# Protect middle page with PROT_NONE
res = mprotect(addr + page_size, page_size, PROT_NONE)
assert res == 0, f"mprotect failed: {res}"

# Output address to parent
sys.stdout.write(f"{addr}\\n")
sys.stdout.flush()

# Keep alive
time.sleep(10)
"""
        proc = subprocess.Popen([sys.executable, "-c", child_code], stdout=subprocess.PIPE, text=True)
        try:
            line = proc.stdout.readline().strip()
            self.assertTrue(line.isdigit(), f"Invalid child output: {line}")
            addr = int(line)
            page_size = 4096

            backend = ProcessVmCaptureBackend()
            plan = CapturePlan(
                mode=CaptureMode.TARGETED.value, allow_stop=True,
                memory_ranges=[(addr, addr + 3 * page_size)],
            )
            policy = CaptureSafetyPolicy(
                max_capture_bytes=1024 * 1024,
            )

            snapshot = backend.capture(pid=proc.pid, plan=plan, policy=policy)

            # Both page 0 and page 2 must be salvaged via process_vm_readv!
            self.assertEqual(snapshot.provenance["bytes_read"], 2 * page_size)
            self.assertIn((addr, addr + page_size), snapshot.captured_ranges)
            self.assertIn((addr + 2 * page_size, addr + 3 * page_size), snapshot.captured_ranges)

            # Verify memory content
            self.assertEqual(snapshot.read_bytes(addr, 12), b"PAGE0_MARKER")
            self.assertEqual(snapshot.read_bytes(addr + 2 * page_size, 12), b"PAGE2_MARKER")

            # Middle guard page returns None
            self.assertIsNone(snapshot.read_bytes(addr + page_size, 12))
        finally:
            if proc.stdout:
                proc.stdout.close()
            proc.kill()
            proc.wait()


if __name__ == "__main__":
    unittest.main()
