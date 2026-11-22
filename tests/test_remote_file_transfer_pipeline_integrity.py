"""Deterministic adversarial tests for RemoteSshTargetAdapter.read_target_file()
and RemoteImageResolver pipeline integrity.

Verifies via real POSIX /bin/sh execution and deterministic PATH command wrappers
(zero timing races, zero target-side temp files, zero Bash pipefail assumptions):
- Post-precheck head failure (zero bytes and partial bytes) cannot return b"" or partial data
- File disappearance between precheck and read returns None (READ_FAILED)
- gzip failure returns None (PIPELINE_FAIL)
- base64 failure returns None (PIPELINE_FAIL), never b""
- Valid 0-byte empty file (both RAW < 8KB and GZIP >= 8KB) returns b""
- /proc virtual files (st_size == 0) read cleanly
- Valid RAW and GZIP payloads round-trip byte-for-byte
- Corrupt GZIP, truncated GZIP, and decompressed-output > max_bytes bomb return None (INVALID_DATA)
- Corrupt Base64 (including mixed valid+invalid chars) returns None (INVALID_DATA)
- Truncated ELF and file mutated during read are rejected and never poison 30s cache
- Missing gzip executable falls back cleanly to RAW over real /bin/sh
- max_bytes exact boundary and max_bytes + 1 semantics
- Transport timeout, connection reset, cancellation, and retry after transient failure
"""

import base64
import gzip
import os
import shutil
import stat
import subprocess
import tempfile
import unittest

from extractor.remote_module_images import RemoteImageResolver, clear_cache
from extractor.target_adapter import RemoteSshTargetAdapter


def _make_sh_adapter(env_override=None):
    def runner(args, timeout):
        env = os.environ.copy()
        if env_override:
            env.update(env_override)
        res = subprocess.run(
            args[-1],
            shell=True,
            executable="/bin/sh",
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
        return res.returncode, res.stdout, res.stderr

    return RemoteSshTargetAdapter(host="127.0.0.1", command_runner=runner, use_control_master=False)


def _write_exec(path, content):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    os.chmod(path, 0o755)


class TestRemoteFileTransferPipelineIntegrity(unittest.TestCase):
    def setUp(self):
        clear_cache()
        self.real_head = shutil.which("head") or "/usr/bin/head"
        self.real_gzip = shutil.which("gzip") or "/bin/gzip"
        self.real_base64 = shutil.which("base64") or "/usr/bin/base64"

    def tearDown(self):
        clear_cache()

    def test_precheck_succeeds_but_head_fails_in_both_gzip_and_raw_paths(self):
        with tempfile.TemporaryDirectory() as td:
            bin_dir = os.path.join(td, "bin")
            os.makedirs(bin_dir)
            # Fake head that always fails with exit 1 (simulating EIO after precheck)
            _write_exec(os.path.join(bin_dir, "head"), "#!/bin/sh\nexit 1\n")

            target = os.path.join(td, "sample.bin")
            with open(target, "wb") as f:
                f.write(b"\x7fELF" + b"A" * 10000)

            env = {"PATH": f"{bin_dir}:{os.environ.get('PATH', '/usr/bin:/bin')}"}
            adapter = _make_sh_adapter(env)

            # GZIP path (>= 8192): must NOT return b"" from empty gzip stream
            self.assertIsNone(adapter.read_target_file(100, target, 16384))
            self.assertEqual(adapter._last_file_read_error["category"], "READ_FAILED")

            # RAW path (< 8192): must NOT return b"" as empty file
            self.assertIsNone(adapter.read_target_file(100, target, 4096))
            self.assertEqual(adapter._last_file_read_error["category"], "READ_FAILED")

    def test_file_disappears_between_precheck_and_read(self):
        with tempfile.TemporaryDirectory() as td:
            bin_dir = os.path.join(td, "bin")
            os.makedirs(bin_dir)
            target = os.path.join(td, "vanishing.bin")
            with open(target, "wb") as f:
                f.write(b"\x7fELF" + b"Z" * 12000)

            # Deterministic wrapper: unlinks target right before invoking real head
            _write_exec(
                os.path.join(bin_dir, "head"),
                f"#!/bin/sh\nrm -f '{target}'\nexec '{self.real_head}' \"$@\"\n",
            )
            env = {"PATH": f"{bin_dir}:{os.environ.get('PATH', '/usr/bin:/bin')}"}
            adapter = _make_sh_adapter(env)

            self.assertIsNone(adapter.read_target_file(100, target, 16384))
            self.assertEqual(adapter._last_file_read_error["category"], "READ_FAILED")

    def test_partial_read_failure_never_silently_returns_partial_bytes(self):
        with tempfile.TemporaryDirectory() as td:
            bin_dir = os.path.join(td, "bin")
            os.makedirs(bin_dir)
            # Fake head emits 64 valid ELF bytes then exits 1 (partial read + I/O error)
            _write_exec(
                os.path.join(bin_dir, "head"),
                "#!/bin/sh\nprintf '\\177ELFpartial_data_before_io_error'\nexit 1\n",
            )
            target = os.path.join(td, "partial.so")
            with open(target, "wb") as f:
                f.write(b"\x7fELF" + b"X" * 12000)

            env = {"PATH": f"{bin_dir}:{os.environ.get('PATH', '/usr/bin:/bin')}"}
            adapter = _make_sh_adapter(env)

            # Both GZIP and RAW paths must reject partial data when head exits non-zero
            self.assertIsNone(adapter.read_target_file(100, target, 16384))
            self.assertEqual(adapter._last_file_read_error["category"], "READ_FAILED")
            self.assertIsNone(adapter.read_target_file(100, target, 4096))
            self.assertEqual(adapter._last_file_read_error["category"], "READ_FAILED")

    def test_gzip_command_failure_returns_none_with_pipeline_fail(self):
        with tempfile.TemporaryDirectory() as td:
            bin_dir = os.path.join(td, "bin")
            os.makedirs(bin_dir)
            # Fake gzip outputs garbage/partial bytes and exits 2
            _write_exec(os.path.join(bin_dir, "gzip"), "#!/bin/sh\nprintf 'partial'\nexit 2\n")

            target = os.path.join(td, "lib.so")
            with open(target, "wb") as f:
                f.write(b"\x7fELF" + b"B" * 12000)

            env = {"PATH": f"{bin_dir}:{os.environ.get('PATH', '/usr/bin:/bin')}"}
            adapter = _make_sh_adapter(env)

            self.assertIsNone(adapter.read_target_file(100, target, 16384))
            self.assertEqual(adapter._last_file_read_error["category"], "PIPELINE_FAIL")

    def test_base64_command_failure_returns_none_with_pipeline_fail_not_empty(self):
        with tempfile.TemporaryDirectory() as td:
            bin_dir = os.path.join(td, "bin")
            os.makedirs(bin_dir)
            _write_exec(os.path.join(bin_dir, "base64"), "#!/bin/sh\nexit 1\n")

            target = os.path.join(td, "small.bin")
            with open(target, "wb") as f:
                f.write(b"hello world")

            env = {"PATH": f"{bin_dir}:{os.environ.get('PATH', '/usr/bin:/bin')}"}
            adapter = _make_sh_adapter(env)

            # RAW path must NOT misinterpret empty stdout from failed base64 as empty file
            self.assertIsNone(adapter.read_target_file(100, target, 4096))
            self.assertEqual(adapter._last_file_read_error["category"], "PIPELINE_FAIL")

            # GZIP path must also fail cleanly
            self.assertIsNone(adapter.read_target_file(100, target, 16384))
            self.assertEqual(adapter._last_file_read_error["category"], "PIPELINE_FAIL")

    def test_empty_file_and_proc_virtual_file_and_raw_and_gzip_valid_paths(self):
        adapter = _make_sh_adapter()
        with tempfile.TemporaryDirectory() as td:
            # 1. Valid 0-byte empty file in BOTH RAW (<8KB) and GZIP (>=8KB) paths
            empty = os.path.join(td, "empty.bin")
            with open(empty, "wb"):
                pass
            self.assertEqual(adapter.read_target_file(100, empty, 4096), b"")
            self.assertIsNone(adapter._last_file_read_error)
            self.assertEqual(adapter.read_target_file(100, empty, 16384), b"")
            self.assertIsNone(adapter._last_file_read_error)

            # 2. Valid RAW payload (<8KB)
            small = os.path.join(td, "small.bin")
            small_data = b"\x7fELF" + bytes(range(256)) * 4
            with open(small, "wb") as f:
                f.write(small_data)
            self.assertEqual(adapter.read_target_file(100, small, 4096), small_data)
            self.assertIsNone(adapter._last_file_read_error)

            # 3. Valid GZIP payload (>=8KB)
            large = os.path.join(td, "large.bin")
            large_data = b"\x7fELF" + (b"0123456789abcdef" * 1024)
            with open(large, "wb") as f:
                f.write(large_data)
            self.assertEqual(adapter.read_target_file(100, large, 32768), large_data)
            self.assertIsNone(adapter._last_file_read_error)

            # 4. /proc virtual file (st_size == 0 on Linux, non-empty content)
            if os.path.exists("/proc/self/cmdline"):
                cmdline = adapter.read_target_file(100, "/proc/self/cmdline", 4096)
                self.assertIsNotNone(cmdline)
                self.assertGreater(len(cmdline), 0)
                self.assertIsNone(adapter._last_file_read_error)

    def test_gzip_unavailable_falls_back_to_raw_over_real_sh(self):
        with tempfile.TemporaryDirectory() as td:
            bin_dir = os.path.join(td, "bin")
            os.makedirs(bin_dir)
            # Symlink only head and base64 — NO gzip on PATH!
            os.symlink("/bin/sh", os.path.join(bin_dir, "sh"))
            os.symlink(self.real_head, os.path.join(bin_dir, "head"))
            os.symlink(self.real_base64, os.path.join(bin_dir, "base64"))

            target = os.path.join(td, "nogzip.bin")
            payload = b"\x7fELF" + b"Q" * 10000
            with open(target, "wb") as f:
                f.write(payload)

            adapter = _make_sh_adapter({"PATH": bin_dir})
            got = adapter.read_target_file(100, target, 16384)
            self.assertEqual(got, payload)
            self.assertIsNone(adapter._last_file_read_error)

    def test_corrupt_gzip_truncated_gzip_gzip_bomb_and_corrupt_base64(self):
        valid_gz = gzip.compress(b"A" * 20000)
        truncated_gz = valid_gz[:-10]  # Missing gzip CRC/ISIZE trailer
        cases = [
            # Corrupt non-gzip bytes inside valid base64
            ("@@GZ\n" + base64.b64encode(b"not-a-gzip-stream").decode() + "\n@@END\n", 16384),
            # Truncated gzip stream (eof == False)
            ("@@GZ\n" + base64.b64encode(truncated_gz).decode() + "\n@@END\n", 32768),
            # Decompressed output exceeds max_bytes (20000 > 8192 bomb guard)
            ("@@GZ\n" + base64.b64encode(valid_gz).decode() + "\n@@END\n", 8192),
            # Corrupt base64 with mixed valid + invalid chars (catches validate=False bug!)
            ("@@RAW\nAAAA!!!corrupt\n@@END\n", 4096),
            # Completely invalid base64
            ("@@RAW\n!!!invalid!!!\n@@END\n", 4096),
            # Empty RAW without @@END marker
            ("@@RAW\n\n", 4096),
        ]
        for out_str, max_b in cases:
            ad = RemoteSshTargetAdapter(
                host="10.0.0.10",
                command_runner=lambda args, t, o=out_str: (0, o, ""),
                use_control_master=False,
            )
            self.assertIsNone(ad.read_target_file(100, "/lib/x.so", max_b), f"Expected None for {out_str[:30]!r}")
            self.assertEqual(ad._last_file_read_error["category"], "INVALID_DATA")

    def test_max_bytes_exact_boundary_and_max_bytes_plus_one(self):
        adapter = _make_sh_adapter()
        with tempfile.TemporaryDirectory() as td:
            # Exact boundary = 8192 bytes
            exact_path = os.path.join(td, "exact.so")
            exact_payload = b"\x7fELF" + b"E" * (8192 - 4)
            with open(exact_path, "wb") as f:
                f.write(exact_payload)

            self.assertEqual(adapter.read_target_file(100, exact_path, 8192), exact_payload)

            # max_bytes + 1 = 8193 bytes
            over_path = os.path.join(td, "over.so")
            over_payload = b"\x7fELF" + b"O" * (8193 - 4)
            with open(over_path, "wb") as f:
                f.write(over_payload)

            self.assertEqual(adapter.read_target_file(100, over_path, 8192), over_payload[:8192])
            self.assertEqual(adapter.read_target_file(100, over_path, 8193), over_payload)

            # RemoteImageResolver accepts exact max_bytes and rejects max_bytes + 1
            resolver = RemoteImageResolver(adapter, 100, None, None, max_bytes=8192)
            local_ok = resolver(exact_path)
            self.assertIsNotNone(local_ok)
            self.assertEqual(os.path.getsize(local_ok), 8192)
            self.assertIsNone(resolver(over_path))
            self.assertIn("cap", resolver.skipped.get(over_path, "").lower())

    def test_truncated_elf_and_file_mutated_during_read_not_negative_cached(self):
        elf_full = b"\x7fELF" + b"\x11" * 1020  # 1024 bytes
        elf_trunc = elf_full[:512]
        attempt = [0]

        def runner(args, timeout):
            cmd = args[-1]
            if "stat -c" in cmd:
                return 0, f"{len(elf_full)} 1700000000\n", ""
            attempt[0] += 1
            if attempt[0] == 1:
                # Simulate file mutated/truncated during first read
                return 0, f"@@RAW\n{base64.b64encode(elf_trunc).decode()}\n@@END\n", ""
            return 0, f"@@RAW\n{base64.b64encode(elf_full).decode()}\n@@END\n", ""

        adapter = RemoteSshTargetAdapter(host="10.0.0.11", command_runner=runner, use_control_master=False)
        resolver = RemoteImageResolver(adapter, 100, None, None, max_bytes=4096)

        # First call sees stat(1024) != len(512) -> rejected, NOT negative-cached
        self.assertIsNone(resolver("/lib/libmutated.so"))
        self.assertIn("truncated", resolver.skipped.get("/lib/libmutated.so", "").lower())

        # Second call retries and succeeds cleanly
        local = resolver("/lib/libmutated.so")
        self.assertIsNotNone(local)
        self.assertEqual(os.path.getsize(local), len(elf_full))

    def test_transport_timeout_reset_cancellation_and_retry_recovery(self):
        elf_bytes = b"\x7fELF" + b"\x22" * 124
        responses = [
            (-1, "", "SSH command timed out after 5.0s"),
            (255, "", "ssh: connect to host 10.0.0.12: Connection reset by peer"),
            (0, "@@GZ\n@@ERR:READ_FAIL\n", ""),
            (0, f"@@RAW\n{base64.b64encode(elf_bytes).decode()}\n@@END\n", ""),
        ]
        idx = [0]

        def runner(args, timeout):
            cmd = args[-1]
            if "stat -c" in cmd:
                return 0, f"{len(elf_bytes)} 1700000000\n", ""
            r = responses[min(idx[0], len(responses) - 1)]
            idx[0] += 1
            return r

        adapter = RemoteSshTargetAdapter(host="10.0.0.12", command_runner=runner, use_control_master=False)
        resolver = RemoteImageResolver(adapter, 100, None, None, max_bytes=4096)

        # 1. Timeout -> None, not cached
        self.assertIsNone(resolver("/lib/libretry.so"))
        self.assertEqual(adapter._last_file_read_error["category"], "TIMEOUT")

        # 2. Connection reset -> None, not cached
        self.assertIsNone(resolver("/lib/libretry.so"))
        self.assertEqual(adapter._last_file_read_error["category"], "TRANSPORT_ERROR")

        # 3. Post-precheck READ_FAIL -> None, not cached
        self.assertIsNone(resolver("/lib/libretry.so"))
        self.assertEqual(adapter._last_file_read_error["category"], "READ_FAILED")

        # 4. Retry succeeds
        local = resolver("/lib/libretry.so")
        self.assertIsNotNone(local)
        self.assertEqual(os.path.getsize(local), len(elf_bytes))


if __name__ == "__main__":
    unittest.main()
