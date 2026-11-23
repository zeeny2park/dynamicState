"""Deterministic tests for 3-hop/xssh single-transaction upfront collection,
RTT-adaptive micro-cache/identity windows, 1-call coalesced collector probe,
and (host, pid, start_time, boot_id, build_id) persistent bundle completion.
"""

import os
import subprocess
import tempfile
import time
import unittest

from extractor.remote_bundle_store import BundleIdentityKey, RemoteCollectedBundleStore
from extractor.target_adapter import RemoteSshTargetAdapter


class TestSingleTransactionPrefetchAndBundleCompletion(unittest.TestCase):
    def test_ensure_remote_collector_coalesces_probe_into_single_ssh_call(self):
        calls = []

        def runner(args, timeout):
            calls.append(args[-1])
            return (
                0,
                "@@PROBE_ARCH=aarch64\n"
                "@@PROBE_FOUND=/tmp/dynamicstate-collector|dynamicstate-collector 1.3.0\n"
                "@@PROBE_DONE\n",
                "",
            )

        ad = RemoteSshTargetAdapter(host="xssh-3hop", command_runner=runner, use_control_master=False)
        res = ad.ensure_remote_collector()
        self.assertTrue(res["deployed"])
        self.assertEqual(res["status"], "ALREADY_PRESENT")
        self.assertEqual(res["collector_path"], "/tmp/dynamicstate-collector")
        self.assertEqual(res["collector_version"], "1.3.0")
        self.assertEqual(len(calls), 1, "Coalesced collector probe must complete in exactly 1 SSH call")

    def test_rtt_adaptive_cache_ttl_eliminates_redundant_maps_liveness_and_identity_probes(self):
        calls = []
        snap_out = (
            "@@LIVENESS\nALIVE\n"
            "@@COMM\nworker\n"
            "@@STAT\n4321 (worker) S 1 4321 4321 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 987654\n"
            "@@STATUS\nVmRSS:\t8192 kB\n"
            "@@MAPS\n00400000-00401000 r-xp 00000000 08:01 123 /usr/bin/worker\n"
            "@@EXE\n/usr/bin/worker\n"
            "@@FP\n123:4096:1700000000\n"
            "@@BOOT\nboot-uuid-1\n"
            "@@OSREL\n6.1.0\n"
            "@@MACH\naarch64\n"
            "@@FDS\n"
            "@@TASKS\n"
            "@@END\n"
        )

        def runner(args, timeout):
            calls.append(args[-1])
            return 0, snap_out, ""

        ad = RemoteSshTargetAdapter(host="xssh-3hop", command_runner=runner, use_control_master=False)
        # Simulate observed 5.0s 3-hop xssh RTT
        ad._observed_rtt_s = 5.0
        self.assertEqual(ad._effective_cache_ttl(2.0), 30.0)

        # Single upfront snapshot populates snapshot, maps, liveness, and identity caches
        snap = ad.prefetch_snapshot(4321, domains=ad.ALL_SNAPSHOT_DOMAINS)
        self.assertIsNotNone(snap)
        self.assertEqual(len(calls), 1)

        # Pin identity from cached snapshot identity
        ident = ad.get_process_identity(4321)
        ad._pinned_identities[4321] = dict(ident)

        # Simulate 4.5s elapsed (> old 2.0s maps/snapshot TTL and > old 0.05s verify window, < 30s RTT-adaptive TTL)
        now = time.monotonic()
        past = now - 4.5
        s_hit = ad._snapshot_cache[4321]
        ad._snapshot_cache[4321] = (past, s_hit[1], s_hit[2])
        id_hit = ad._last_identity_cache[4321]
        ad._last_identity_cache[4321] = (past, id_hit[1])
        ad._liveness_cache[4321] = (past, True)

        # Repeated maps, liveness, and pinned identity verification must make ZERO additional SSH calls!
        maps = ad.get_proc_maps(4321)
        self.assertEqual(len(maps), 1)
        alive, err = ad.check_liveness(4321)
        self.assertTrue(alive)
        self.assertIsNone(err)
        ok_pin, pin_err = ad.verify_pinned_identity(4321, _allow_recent_sec=0.05)
        self.assertTrue(ok_pin, pin_err)
        self.assertEqual(len(calls), 1, "No redundant SSH calls should occur within RTT-adaptive window")

    def test_collect_upfront_bundle_single_exec_with_optional_t2_delta_over_real_sh(self):
        calls = []

        def local_sh(args, timeout):
            calls.append(args[-1])
            res = subprocess.run(args[-1], shell=True, executable="/bin/sh", capture_output=True, text=True, timeout=timeout)
            return res.returncode, res.stdout, res.stderr

        ad = RemoteSshTargetAdapter(host="127.0.0.1", command_runner=local_sh, use_control_master=False)
        my_pid = os.getpid()
        bundle = ad.collect_upfront_bundle(my_pid, delta_sample_interval_s=0.05)
        self.assertIsNotNone(bundle)
        self.assertEqual(bundle["pid"], my_pid)
        self.assertIn("snapshot", bundle)
        self.assertIn("identity", bundle)
        self.assertGreaterEqual(len(bundle["delta_tasks_t2"]), 1)
        # Wave 1 + T2 delta must complete in 1-2 calls max (1 for snapshot+T2, at most 1 if ELF header fetched)
        self.assertLessEqual(len(calls), 2)

    def test_bundle_store_identity_key_prevents_pid_reuse_and_build_id_mismatch(self):
        with tempfile.TemporaryDirectory() as td:
            store = RemoteCollectedBundleStore(td)
            k1 = BundleIdentityKey(
                host="xssh-3hop",
                pid=4321,
                start_time="100001",
                boot_id="boot-A",
                build_id="deadbeef1234",
            )
            store.save_bundle(
                k1,
                snapshot={"maps": "00400000-00401000 r-xp 00000000 08:01 1 /app\n", "stat": "4321 (app) S 1 ..."},
                identity={"pid": 4321, "executable": "/app", "start_time": "100001", "boot_id": "boot-A", "build_id": "deadbeef1234"},
                investigation_id="inv-001",
            )

            # Exact match succeeds
            loaded = store.load_bundle(k1)
            self.assertIsNotNone(loaded)
            self.assertEqual(loaded["investigation_id"], "inv-001")

            # Same (host, pid, build_id) with DIFFERENT start_time (PID reuse!) -> MUST NOT match
            k_reused_pid = BundleIdentityKey(
                host="xssh-3hop",
                pid=4321,
                start_time="200002",
                boot_id="boot-A",
                build_id="deadbeef1234",
            )
            self.assertIsNone(store.load_bundle(k_reused_pid))
            self.assertIsNone(store.find_latest(host="xssh-3hop", pid=4321, build_id="deadbeef1234", start_time="200002"))

            # Same (host, pid) with DIFFERENT build_id -> MUST NOT match
            self.assertIsNone(store.find_latest(host="xssh-3hop", pid=4321, build_id="cafebabe9999"))

            # Matching (host, pid, build_id) finds latest bundle for offline completion
            found = store.find_latest(host="xssh-3hop", pid=4321, build_id="DEADBEEF1234")
            self.assertIsNotNone(found)
            self.assertEqual(found["investigation_id"], "inv-001")

            # Invalidation removes bundle cleanly
            self.assertTrue(store.invalidate(k1))
            self.assertIsNone(store.load_bundle(k1))

    def test_hydrate_from_bundle_serves_all_metadata_with_zero_ssh_calls(self):
        ssh_calls = [0]

        def fail_if_called(args, timeout):
            ssh_calls[0] += 1
            return 255, "", "ssh: Connection refused (must not call SSH in hydrated mode)"

        ad = RemoteSshTargetAdapter(host="xssh-3hop", command_runner=fail_if_called, use_control_master=False)
        bundle = {
            "pid": 4321,
            "identity": {
                "pid": 4321,
                "executable": "/usr/bin/worker",
                "start_time": "987654",
                "boot_id": "boot-A",
                "build_id": "deadbeef1234",
                "process_identity": "4321:987654:boot-A",
            },
            "snapshot": {
                "terminated": False,
                "exe": "/usr/bin/worker",
                "stat": "4321 (worker) S 1 4321 4321 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 987654",
                "status": "Name:\tworker\nVmRSS:\t4096 kB\n",
                "maps": "00400000-00401000 r-xp 00000000 08:01 1 /usr/bin/worker\n",
                "boot_id": "boot-A",
                "osrelease": "6.1.0",
            },
        }
        self.assertTrue(ad.hydrate_from_bundle(bundle))

        # All metadata queries must succeed purely from hydrated bundle with ZERO SSH calls!
        alive, err = ad.check_liveness(4321)
        self.assertTrue(alive)
        self.assertIsNone(err)
        ident = ad.get_process_identity(4321)
        self.assertEqual(ident["build_id"], "deadbeef1234")
        ok_pin, pin_err = ad.verify_pinned_identity(4321, _allow_recent_sec=0.05)
        self.assertTrue(ok_pin, pin_err)
        maps = ad.get_proc_maps(4321)
        self.assertEqual(len(maps), 1)
        self.assertEqual(maps[0]["pathname"], "/usr/bin/worker")
        self.assertEqual(ssh_calls[0], 0, "Hydrated bundle mode must make zero SSH calls")


if __name__ == "__main__":
    unittest.main()
