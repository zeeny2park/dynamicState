"""Tests for remote memory slice coalescing and remote SSH connection edge-case resilience.

Verifies:
1. _coalesce_memory_slices & read_memory_batch merge duplicate, overlapping, and adjacent slices
   into minimal remote reads while unpacking exact original slices in original order.
2. read_memory_batch skips redundant check_liveness SSH round-trip on SSH transport/timeout errors.
3. read_memory never misclassifies SSH transport failure on empty output as TARGET_TERMINATED.
4. Permanent host-key verification failure and unresolvable hostname fast-fail without repeated SSH calls,
   and reset_transport_failure() clears the cached state.
5. get_process_identity(force=True) never falls back to stale cached identity on SSH transport failure.
6. _with_daemon skips opening a daemon channel when permanent transport error or expired deadline is active,
   and safely handles TimeoutError without leaking unhandled exceptions.
"""

import base64
import time
import unittest

from extractor.target_adapter import RemoteSshTargetAdapter


class TestRemoteSliceCoalescingAndResilience(unittest.TestCase):
    """Verifies speed optimizations (slice coalescing, fast-fail) and connection exception safety."""

    def test_coalesce_memory_slices_merges_duplicates_overlaps_and_adjacent(self):
        # 5 slices: 2 duplicates + 1 overlapping + 1 adjacent (within 256B gap) + 1 far away
        slices = [
            (0x1000, 16),
            (0x1000, 16),     # duplicate
            (0x1008, 24),     # overlapping (ends at 0x1020)
            (0x1060, 8),      # adjacent (gap 0x40 = 64B <= 256B, ends at 0x1068)
            (0x9000, 32),     # separate region
            (0x2000, 0),      # zero-length
        ]
        vmas = [{'start_int': 0x1000, 'end_int': 0x2000, 'is_readable': True, 'permissions': 'rw-p'}, {'start_int': 0x9000, 'end_int': 0xa000, 'is_readable': True, 'permissions': 'rw-p'}]
        merged, mapping = RemoteSshTargetAdapter._coalesce_memory_slices(slices, mappings=vmas)
        self.assertEqual(len(merged), 2)
        self.assertEqual(merged[0], (0x1000, 0x68))
        self.assertEqual(merged[1], (0x9000, 32))
        self.assertEqual(mapping[0], (0, 0, 16))
        self.assertEqual(mapping[1], (0, 0, 16))
        self.assertEqual(mapping[2], (0, 8, 24))
        self.assertEqual(mapping[3], (0, 0x60, 8))
        self.assertEqual(mapping[4], (1, 0, 32))
        self.assertEqual(mapping[5], (-1, 0, 0))

    def test_read_memory_batch_unpacks_coalesced_slices_in_one_ssh_call(self):
        # Simulated 0x68-byte region at 0x1000 and 32-byte region at 0x9000
        region0 = bytes(range(0x68))
        region1 = bytes(range(200, 232))
        b64_0 = base64.b64encode(region0).decode("ascii")
        b64_1 = base64.b64encode(region1).decode("ascii")
        ssh_cmds = []

        def runner(args, timeout):
            ssh_cmds.append(args[-1])
            return 0, f"0|{b64_0}\n1|{b64_1}\n", ""

        adapter = RemoteSshTargetAdapter(host="10.0.0.1", command_runner=runner, use_control_master=False)
        adapter.verify_pinned_identity = lambda pid, **kw: (True, None)
        adapter._maps_micro_cache[1234] = (time.monotonic(), [
            {'start_int': 0x1000, 'end_int': 0x2000, 'is_readable': True, 'permissions': 'rw-p'},
            {'start_int': 0x9000, 'end_int': 0xa000, 'is_readable': True, 'permissions': 'rw-p'},
        ])

        slices = [(0x1000, 8), (0x1000, 8), (0x1004, 12), (0x1060, 8), (0x9000, 32)]
        res = adapter.read_memory_batch(1234, slices)
        self.assertEqual(len(ssh_cmds), 1)
        # Only 2 dd pipelines should appear in the remote script instead of 5
        self.assertEqual(ssh_cmds[0].count("dd if=/proc/1234/mem"), 2)
        self.assertEqual(res[0], (region0[0:8], "OBSERVED", None))
        self.assertEqual(res[1], (region0[0:8], "OBSERVED", None))
        self.assertEqual(res[2], (region0[4:16], "OBSERVED", None))
        self.assertEqual(res[3], (region0[0x60:0x68], "OBSERVED", None))
        self.assertEqual(res[4], (region1, "OBSERVED", None))

    def test_read_memory_batch_skips_redundant_liveness_on_ssh_timeout(self):
        calls = [0]

        def timeout_runner(args, timeout):
            calls[0] += 1
            return -1, "", "SSH command timed out after 5.0s"

        adapter = RemoteSshTargetAdapter(host="10.0.0.1", command_runner=timeout_runner, use_control_master=False)
        adapter.verify_pinned_identity = lambda pid, **kw: (True, None)

        res = adapter.read_memory_batch(1234, [(0x1000, 16), (0x5000, 16)])
        self.assertEqual(calls[0], 1, "Must not issue redundant check_liveness SSH call after SSH timeout")
        self.assertEqual(res[0][1], "UNAVAILABLE")
        self.assertIn("TIMEOUT", res[0][2])

    def test_read_memory_empty_output_transport_error_not_misclassified_as_terminated(self):
        call_n = [0]

        def runner(args, timeout):
            call_n[0] += 1
            if call_n[0] == 1:
                return 0, "", ""  # empty output from dd
            return 255, "", "ssh: connect to host 10.0.0.1: Connection reset by peer"

        adapter = RemoteSshTargetAdapter(host="10.0.0.1", command_runner=runner, use_control_master=False)
        adapter.verify_pinned_identity = lambda pid, **kw: (True, None)

        data, status, err = adapter.read_memory(1234, 0x1000, 16)
        self.assertIsNone(data)
        self.assertEqual(status, "UNAVAILABLE", "SSH transport failure during liveness check must not be TARGET_TERMINATED")
        self.assertIn("transport", (err or "").lower())

    def test_host_key_and_dns_failures_fast_fail_and_reset(self):
        for err_msg, expected_cls in (
            ("Host key verification failed.", "HOST_KEY_ERROR"),
            ("ssh: Could not resolve hostname bad.local: Name or service not known", "TRANSPORT_ERROR"),
        ):
            calls = [0]

            def runner(args, timeout, msg=err_msg):
                calls[0] += 1
                return 255, "", msg

            adapter = RemoteSshTargetAdapter(host="bad.local", command_runner=runner, use_control_master=False)
            for _ in range(4):
                rc, _, err = adapter.run_ssh("echo hi")
                self.assertNotEqual(rc, 0)
                self.assertEqual(RemoteSshTargetAdapter.classify_remote_error(rc, err), expected_cls)
            self.assertEqual(calls[0], 1, f"Permanent error '{err_msg}' must fast-fail subsequent calls")

            adapter.reset_transport_failure()
            adapter.run_ssh("echo retry")
            self.assertEqual(calls[0], 2)

    def test_get_process_identity_force_does_not_return_stale_cache_on_ssh_failure(self):
        fail_now = [False]

        def runner(args, timeout):
            if fail_now[0]:
                return -1, "", "SSH command timed out after 5.0s"
            out = "\n".join([
                "@@EXE", "/usr/bin/app",
                "@@STAT", "1234 (app) S 1 1 1 0 -1 4194304 0 0 0 0 0 0 0 0 20 0 1 0 9999 0 0",
                "@@BOOT", "boot-1",
                "@@FP", "10:20:30",
                "@@MACH", "x86_64",
                "@@END",
            ])
            return 0, out, ""

        adapter = RemoteSshTargetAdapter(host="10.0.0.1", command_runner=runner, use_control_master=False)
        id1 = adapter.get_process_identity(1234)
        self.assertEqual(id1["start_time"], "9999")

        fail_now[0] = True
        # force=False may use recent cache
        id_cached = adapter.get_process_identity(1234, force=False)
        self.assertEqual(id_cached["start_time"], "9999")
        # Backdate cache past 60s TTL; expired cache must NOT be returned when SSH fails
        ts_old, val_old = adapter._last_identity_cache[1234]
        adapter._last_identity_cache[1234] = (ts_old - 120.0, val_old)
        id_expired = adapter.get_process_identity(1234, force=True)
        self.assertEqual(id_expired["start_time"], "")

    def test_with_daemon_skips_open_on_permanent_failure_or_expired_deadline(self):
        opened = [0]

        def opener(args):
            opened[0] += 1
            raise AssertionError("Daemon must not be opened")

        adapter = RemoteSshTargetAdapter(
            host="10.0.0.1",
            collector_path="/tmp/collector",
            stream_opener=opener,
            use_control_master=False,
        )
        adapter._permanent_transport_error = ("Host key verification failed", "changed")
        self.assertIsNone(adapter._with_daemon(lambda ch: ch))
        self.assertEqual(opened[0], 0)

        adapter.reset_transport_failure()
        with adapter.collection_deadline(0.01):
            time.sleep(0.02)
            self.assertIsNone(adapter._with_daemon(lambda ch: ch))
        self.assertEqual(opened[0], 0)


if __name__ == "__main__":
    unittest.main()
