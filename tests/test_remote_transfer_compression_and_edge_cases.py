"""Tests for remote file gzip-compressed transfer, find_processes early stop,
ensure_remote_collector fast-fail, and RemoteImageResolver transient-failure cache safety.
"""

import base64
import gzip
import time
import unittest

from extractor.remote_module_images import RemoteImageResolver, clear_cache
from extractor.target_adapter import RemoteSshTargetAdapter


class TestRemoteTransferCompressionAndEdgeCases(unittest.TestCase):
    def setUp(self):
        clear_cache()

    def tearDown(self):
        clear_cache()

    def test_read_target_file_decompresses_gzip_payload_and_falls_back_to_raw(self):
        raw_elf = b"\x7fELF" + (b"\x00\x11\x22\x33" * 4096)  # 16KB+ compressible payload
        gz_b64 = base64.b64encode(gzip.compress(raw_elf)).decode("ascii")
        raw_b64 = base64.b64encode(raw_elf).decode("ascii")

        # 1. Gzip path
        seen_cmds = []
        ad_gz = RemoteSshTargetAdapter(
            host="10.0.0.1",
            command_runner=lambda args, t: (seen_cmds.append(args[-1]), (0, f"@@GZ\n{gz_b64}\n", ""))[1],
            use_control_master=False,
        )
        got_gz = ad_gz.read_target_file(1234, "/lib/libc.so.6", 65536)
        self.assertEqual(got_gz, raw_elf)
        self.assertIn("gzip", seen_cmds[0])
        self.assertLess(len(gz_b64), len(raw_b64), "Gzip payload should be significantly smaller than raw base64")

        # 2. Raw fallback path (target without gzip)
        ad_raw = RemoteSshTargetAdapter(
            host="10.0.0.2",
            command_runner=lambda args, t: (0, f"@@RAW\n{raw_b64}\n", ""),
            use_control_master=False,
        )
        got_raw = ad_raw.read_target_file(1234, "/lib/libc.so.6", 65536)
        self.assertEqual(got_raw, raw_elf)

        # 3. Corrupted gzip returns None safely without crashing
        ad_bad = RemoteSshTargetAdapter(
            host="10.0.0.3",
            command_runner=lambda args, t: (0, "@@GZ\nnot_valid_gzip_base64!!!\n", ""),
            use_control_master=False,
        )
        self.assertIsNone(ad_bad.read_target_file(1234, "/lib/libc.so.6", 65536))

    def test_find_processes_early_stops_on_exact_name_and_build_id_match(self):
        proc_list = "\n".join([
            "100|worker|/usr/bin/worker|/usr/bin/worker",
            "101|worker|/usr/bin/worker|/usr/bin/worker",
            "102|worker|/usr/bin/worker|/usr/bin/worker",
        ])
        adapter = RemoteSshTargetAdapter(
            host="10.0.0.1",
            command_runner=lambda args, t: (0, proc_list, ""),
            use_control_master=False,
        )
        ident_calls = []

        def fake_ident(pid, force=False):
            ident_calls.append(pid)
            return {"pid": pid, "build_id": "deadbeef1234"}

        adapter.get_process_identity = fake_ident
        found = adapter.find_processes(process_name="worker", companion_build_id="deadbeef1234")
        self.assertEqual(len(ident_calls), 1, "Must stop probing candidates once exact name + build_id matches")
        self.assertTrue(found[0]["build_id_match"])

    def test_ensure_remote_collector_fast_fails_on_unreachable_target(self):
        calls = [0]

        def conn_refused(args, t):
            calls[0] += 1
            return 255, "", "ssh: connect to host 10.0.0.9 port 22: Connection refused"

        adapter = RemoteSshTargetAdapter(
            host="10.0.0.9",
            command_runner=conn_refused,
            use_control_master=False,
        )
        res = adapter.ensure_remote_collector()
        self.assertFalse(res["deployed"])
        self.assertEqual(res["status"], "FALLBACK_SHELL")
        self.assertEqual(calls[0], 1, "Must not probe fallback destinations when initial SSH probe fails")
        self.assertIn("TRANSPORT_ERROR", res["reason"])

    def test_remote_image_resolver_does_not_poison_cache_on_transient_timeout_and_respects_deadline(self):
        calls = [0]
        elf_bytes = b"\x7fELF" + b"\x00" * 60

        class FlakyAdapter:
            def target_host(self):
                return "10.0.0.5"

            def remaining_deadline_sec(self):
                return self._rem

            def stat_target_file(self, pid, path):
                return (len(elf_bytes), 1700000000)

            def read_target_file(self, pid, path, max_bytes):
                calls[0] += 1
                if calls[0] == 1:
                    raise TimeoutError("transient SSH timeout")
                return elf_bytes

        ad = FlakyAdapter()
        ad._rem = 5.0
        resolver = RemoteImageResolver(ad, 1234, None, None)

        # First call fails transiently -> returns None but must NOT poison global cache
        self.assertIsNone(resolver("/lib/libfoo.so"))
        # Second call succeeds immediately after transient recovery
        local_path = resolver("/lib/libfoo.so")
        self.assertIsNotNone(local_path)
        self.assertEqual(calls[0], 2)

        # Expired deadline skips remote calls completely
        ad._rem = -0.1
        self.assertIsNone(resolver("/lib/libbar.so"))
        self.assertEqual(calls[0], 2)


if __name__ == "__main__":
    unittest.main()
