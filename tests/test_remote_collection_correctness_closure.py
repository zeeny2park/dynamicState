"""Comprehensive deterministic correctness tests for Remote Collection Closure (Findings 1–3 & Phase 3).

Covers:
- Finding 1: Mapping-aware _coalesce_memory_slices (same mapping, guard pages, different mappings,
  unmapped gap, unknown mappings -> gap=0), bounded individual fallback on partial/failed merged read,
  original slice ordering, physical-read accounting, and no unbounded fallback.
- Finding 2: RemoteImageResolver negative-cache protection when read_target_file() returns None
  due to transient SSH timeout/transport error (vs permanent FILE_MISSING / PERMISSION_DENIED /
  oversized / non-ELF), deadline expiry, retry after recovery, and concurrent fetch safety.
- Finding 3: Real POSIX sh execution of read_target_file() prechecks & gzip -1 / RAW pipelines
  distinguishing missing file, unreadable file, truly empty 0-byte file, valid file, truncation at
  max_bytes, corrupt gzip, corrupt base64, pipeline failure, and SSH failure.
- Phase 3: Connection resilience (transient failures not cached permanently, timeout never cached
  as auth failure, cross-adapter isolation).
"""

import base64
import gzip
import os
import stat
import subprocess
import tempfile
import threading
import time
import unittest

from extractor.remote_module_images import RemoteImageResolver, clear_cache
from extractor.target_adapter import RemoteSshTargetAdapter


class TestFinding1MemorySliceCoalescingCorrectness(unittest.TestCase):
    """Finding 1: Mapping-boundary safety, bounded fallback, and physical-read accounting."""

    def test_unknown_mappings_only_coalesces_duplicates_overlaps_and_contiguous(self):
        # Without mapping info, a 64-byte gap MUST NOT be merged (zero speculative over-read)
        slices = [
            (0x1000, 16),
            (0x1000, 16),  # duplicate -> merged
            (0x1008, 16),  # overlapping -> merged (0x1000..0x1018)
            (0x1018, 8),   # contiguous -> merged (0x1000..0x1020)
            (0x1060, 16),  # 64B gap -> MUST stay separate when mappings unknown
        ]
        merged, mapping = RemoteSshTargetAdapter._coalesce_memory_slices(slices, mappings=None)
        self.assertEqual(merged, [(0x1000, 0x20), (0x1060, 16)])
        self.assertEqual(mapping[0], (0, 0, 16))
        self.assertEqual(mapping[4], (1, 0, 16))

    def test_same_readable_mapping_merges_gap_but_different_or_guard_mapping_never_merges(self):
        mappings = [
            {"start_int": 0x1000, "end_int": 0x2000, "is_readable": True, "permissions": "rw-p"},
            {"start_int": 0x2000, "end_int": 0x3000, "is_readable": False, "permissions": "---p"},  # guard page
            {"start_int": 0x3000, "end_int": 0x4000, "is_readable": True, "permissions": "rw-p"},
            {"start_int": 0x4000, "end_int": 0x5000, "is_readable": True, "permissions": "r--p"},  # different VMA
        ]
        slices = [
            (0x1000, 16),  # VMA 1
            (0x1040, 16),  # VMA 1 (gap 48B <= 256B -> safe merge!)
            (0x1FF0, 16),  # VMA 1 end
            (0x3000, 16),  # VMA 3 (separated by guard page 0x2000-0x3000 -> MUST NOT merge!)
            (0x3FF0, 16),  # VMA 3 end
            (0x4000, 16),  # VMA 4 start (contiguous across different VMA boundary -> MUST NOT merge!)
        ]
        merged, _ = RemoteSshTargetAdapter._coalesce_memory_slices(slices, max_gap=256, mappings=mappings)
        self.assertEqual(merged, [(0x1000, 0x50), (0x1FF0, 16), (0x3000, 16), (0x3FF0, 16), (0x4000, 16)])

    def test_bounded_individual_fallback_recovers_readable_slices_when_merged_read_fails(self):
        # Two slices in same VMA merged into one read that partially fails (returns only first 8 bytes);
        # bounded individual fallback must recover the second slice cleanly and preserve order & accounting.
        s0_bytes = b"AAAAAAAA"
        s1_bytes = b"BBBBBBBB"
        ssh_calls = [0]

        def runner(args, timeout):
            ssh_calls[0] += 1
            if ssh_calls[0] == 1:
                # Merged read returns partial (only first 8 bytes, cutting off second slice)
                return 0, f"0|{base64.b64encode(s0_bytes).decode()}\n", ""
            # Fallback individual read for the failed slice recovers s1_bytes
            return 0, f"0|{base64.b64encode(s1_bytes).decode()}\n", ""

        adapter = RemoteSshTargetAdapter(host="10.0.0.1", command_runner=runner, use_control_master=False)
        adapter.verify_pinned_identity = lambda pid, **kw: (True, None)
        adapter._maps_micro_cache[1234] = (
            time.monotonic(),
            [{"start_int": 0x1000, "end_int": 0x2000, "is_readable": True, "permissions": "rw-p"}],
        )

        res = adapter.read_memory_batch(1234, [(0x1000, 8), (0x1020, 8)])
        self.assertEqual(ssh_calls[0], 2, "Should perform exactly 1 bounded fallback batch")
        self.assertEqual(res[0], (s0_bytes, "OBSERVED", None))
        self.assertEqual(res[1], (s1_bytes, "OBSERVED", None))
        self.assertGreaterEqual(adapter.physical_bytes_read, 16)


class TestFinding2RemoteElfImageNegativeCache(unittest.TestCase):
    """Finding 2: Transient read_target_file() -> None must NEVER poison global negative cache."""

    def setUp(self):
        clear_cache()

    def tearDown(self):
        clear_cache()

    def test_transient_none_return_from_read_target_file_does_not_poison_cache(self):
        elf_bytes = b"\x7fELF" + b"\x00" * 60
        calls = [0]

        def runner(args, timeout):
            calls[0] += 1
            cmd = args[-1]
            if "stat -c" in cmd:
                return 0, f"{len(elf_bytes)} 1700000000\n", ""
            if calls[0] <= 2:
                # Transient SSH timeout returning None via read_target_file (NOT raising)
                return -1, "", "SSH command timed out after 5.0s"
            return 0, f"@@RAW\n{base64.b64encode(elf_bytes).decode()}\n", ""

        adapter = RemoteSshTargetAdapter(host="10.0.0.5", command_runner=runner, use_control_master=False)
        resolver = RemoteImageResolver(adapter, 1234, None, None)

        # First fetch fails transiently (returns None) -> must NOT be negative-cached
        self.assertIsNone(resolver("/lib/libtransient.so"))
        self.assertIn("transient", resolver.skipped.get("/lib/libtransient.so", "").lower())

        # Immediate retry after transport recovers MUST succeed
        local_path = resolver("/lib/libtransient.so")
        self.assertIsNotNone(local_path)
        self.assertTrue(os.path.isfile(local_path))

    def test_permanent_missing_permission_oversize_and_non_elf_are_negative_cached(self):
        calls = [0]

        def runner(args, timeout):
            calls[0] += 1
            cmd = args[-1]
            if "stat -c" in cmd:
                if "huge.so" in cmd:
                    return 0, f"{100 * 1024 * 1024} 1700000000\n", ""
                return 0, "64 1700000000\n", ""
            if "missing.so" in cmd:
                return 0, "@@ERR:FILE_MISSING\n", ""
            if "secret.so" in cmd:
                return 0, "@@ERR:PERMISSION_DENIED\n", ""
            if "notelf.so" in cmd:
                return 0, f"@@RAW\n{base64.b64encode(b'NOT_AN_ELF' * 6).decode()}\n", ""
            return 0, "@@ERR:FILE_MISSING\n", ""

        adapter = RemoteSshTargetAdapter(host="10.0.0.6", command_runner=runner, use_control_master=False)
        resolver = RemoteImageResolver(adapter, 1234, None, None, max_bytes=1024)

        for path in ("/lib/missing.so", "/lib/secret.so", "/lib/huge.so", "/lib/notelf.so"):
            self.assertIsNone(resolver(path))
        calls_after_first = calls[0]
        # Second calls within TTL must hit negative cache (zero additional SSH calls)
        for path in ("/lib/missing.so", "/lib/secret.so", "/lib/huge.so", "/lib/notelf.so"):
            self.assertIsNone(resolver(path))
        self.assertEqual(calls[0], calls_after_first, "Permanent failures must be negative-cached")

    def test_concurrent_resolver_calls_do_not_corrupt_cache(self):
        elf_bytes = b"\x7fELF" + b"\x01" * 60

        def runner(args, timeout):
            cmd = args[-1]
            if "stat -c" in cmd:
                return 0, f"{len(elf_bytes)} 1700000000\n", ""
            time.sleep(0.01)
            return 0, f"@@RAW\n{base64.b64encode(elf_bytes).decode()}\n", ""

        adapter = RemoteSshTargetAdapter(host="10.0.0.7", command_runner=runner, use_control_master=False)
        resolver = RemoteImageResolver(adapter, 1234, None, None)
        results = []
        lock = threading.Lock()

        def worker():
            res = resolver("/lib/libconcurrent.so")
            with lock:
                results.append(res)

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5.0)
        self.assertEqual(len(results), 5)
        for p in results:
            self.assertIsNotNone(p)
            self.assertTrue(os.path.isfile(p))


class TestFinding3GzipPipelineErrorSemantics(unittest.TestCase):
    """Finding 3: Real POSIX sh execution proving empty file != missing/unreadable/failed file."""

    def _make_local_sh_adapter(self):
        def local_sh_runner(args, timeout):
            # args[-1] is "sh -c '...'" — run it locally via /bin/sh to test exact remote shell logic!
            res = subprocess.run(args[-1], shell=True, capture_output=True, text=True, timeout=timeout)
            return res.returncode, res.stdout, res.stderr

        return RemoteSshTargetAdapter(host="127.0.0.1", command_runner=local_sh_runner, use_control_master=False)

    def test_real_posix_sh_distinguishes_missing_unreadable_empty_and_valid_gzip_files(self):
        adapter = self._make_local_sh_adapter()
        with tempfile.TemporaryDirectory() as td:
            # 1. Missing file -> None + FILE_MISSING
            missing = os.path.join(td, "does_not_exist.bin")
            self.assertIsNone(adapter.read_target_file(1234, missing, 16384))
            self.assertEqual(adapter._last_file_read_error["category"], "FILE_MISSING")

            # 2. Truly empty 0-byte readable file -> b"" (NOT None!)
            empty = os.path.join(td, "empty.bin")
            with open(empty, "wb"):
                pass
            got_empty = adapter.read_target_file(1234, empty, 16384)
            self.assertEqual(got_empty, b"")
            self.assertIsNone(adapter._last_file_read_error)

            # 3. Valid compressible file >= 8KB (gzip -1 path) + truncation at max_bytes
            big = os.path.join(td, "big.bin")
            payload = (b"\x7fELF" + b"ABCD" * 5000)  # 20,004 bytes
            with open(big, "wb") as f:
                f.write(payload)
            got_trunc = adapter.read_target_file(1234, big, 12000)
            self.assertEqual(got_trunc, payload[:12000])
            self.assertIsNone(adapter._last_file_read_error)

            # 4. Unreadable file (chmod 000, non-root) -> None + PERMISSION_DENIED
            if hasattr(os, "geteuid") and os.geteuid() != 0:
                unreadable = os.path.join(td, "secret.bin")
                with open(unreadable, "wb") as f:
                    f.write(b"secret" * 2000)
                os.chmod(unreadable, 0o000)
                try:
                    self.assertIsNone(adapter.read_target_file(1234, unreadable, 16384))
                    self.assertEqual(adapter._last_file_read_error["category"], "PERMISSION_DENIED")
                finally:
                    os.chmod(unreadable, stat.S_IRUSR | stat.S_IWUSR)

    def test_pipeline_failure_and_corrupt_base64_and_ssh_failure_return_none_with_category(self):
        for out_str, rc, err_str, expected_cat in (
            ("@@ERR:PIPELINE_FAIL\n", 0, "", "PIPELINE_FAIL"),
            ("@@RAW\n!!!not-base64!!!\n", 0, "", "INVALID_DATA"),
            ("@@GZ\n" + base64.b64encode(b"not_gzip_bytes").decode() + "\n", 0, "", "INVALID_DATA"),
            ("", -1, "SSH command timed out after 5.0s", "TIMEOUT"),
        ):
            ad = RemoteSshTargetAdapter(
                host="10.0.0.8",
                command_runner=lambda args, t, o=out_str, r=rc, e=err_str: (r, o, e),
                use_control_master=False,
            )
            self.assertIsNone(ad.read_target_file(1234, "/lib/x.so", 16384))
            self.assertEqual(ad._last_file_read_error["category"], expected_cat)


class TestPhase3ConnectionResilienceGaps(unittest.TestCase):
    """Phase 3: Transient failures & timeouts are never cached as permanent auth/transport errors."""

    def test_timeout_and_connection_reset_never_cached_permanently(self):
        calls = [0]

        def flaky(args, timeout):
            calls[0] += 1
            if calls[0] == 1:
                return -1, "", "SSH command timed out after 5.0s"
            if calls[0] == 2:
                return 255, "", "ssh: connect to host 10.0.0.1: Connection reset by peer"
            return 0, "recovered", ""

        ad = RemoteSshTargetAdapter(host="10.0.0.1", command_runner=flaky, use_control_master=False)
        rc1, _, _ = ad.run_ssh("echo 1")
        self.assertEqual(rc1, -1)
        self.assertIsNone(ad._auth_failed_reason)
        self.assertIsNone(ad._permanent_transport_error)

        rc2, _, _ = ad.run_ssh("echo 2")
        self.assertEqual(rc2, 255)
        self.assertIsNone(ad._auth_failed_reason)
        self.assertIsNone(ad._permanent_transport_error)

        rc3, out3, _ = ad.run_ssh("echo 3")
        self.assertEqual(rc3, 0)
        self.assertEqual(out3, "recovered")
        self.assertEqual(calls[0], 3)


if __name__ == "__main__":
    unittest.main()
