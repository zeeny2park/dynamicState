"""IMP-022: the cost of a remote diagnosis in ssh commands.

Real native collector behind a local ``sh`` transport (pattern of test_imp006 / test_imp021).  Measured before the
change: ~800 ssh invocations per ``diagnose()`` on the deadlock fixture, 80 % of them identity re-verification
(readlink + ELF header + stat + boot_id per read), the rest /proc/maps, liveness and status reads.

Design after the change: identity, maps, status and liveness are daemon exchanges (``IDENT`` / ``PROCFILE``) on the
persistent channel; the ELF header of an executable image is transferred once and cached by (path, ino:size:mtime).
Remaining one-shot ssh commands: deploy probes, ``ls -l /proc/PID/fd``-style recipe reads, library image reads.
Bound derived from that: ssh invocations <= 15 per diagnose (measured: 7) (daemon open 1, library/file/stat reads ~10, slack for
retries); the daemon carries everything else.
"""
import threading
import unittest

import tests.test_imp006_remote_diagnose as base
from extractor.expert_diagnostic_engine import diagnose
from extractor.target_adapter import RemoteSshTargetAdapter

MAX_SSH_PER_DIAGNOSE = 15


class Counter:
    def __init__(self):
        self.runs = 0
        self.opens = 0
        self.lock = threading.Lock()

    def runner(self, args, timeout, input_bytes=None):
        with self.lock:
            self.runs += 1
        return base.local_sh_runner(args, timeout, input_bytes)

    def opener(self, args):
        with self.lock:
            self.opens += 1
        return base.local_sh_stream(args)

    @property
    def total(self):
        return self.runs + self.opens


class RemoteCommandCostTests(base.RemoteDiagnoseTests):
    """Reuses the IMP-006 fixture plumbing (collector build, fixtures, spec); its own tests are disabled below."""

    def test_diagnose_ssh_command_count_and_equal_results(self):
        proc, binary, _ = self._launch("proc_thread_circular_deadlock.c", ready=False)
        loc = diagnose(proc.pid, binary, corpus_dir=self.corpus).to_dict()
        cnt = Counter()
        spec = self._spec(command_runner=cnt.runner, stream_opener=cnt.opener)
        rem = diagnose(proc.pid, binary, corpus_dir=self.corpus, target=spec).to_dict()
        print("\n[imp022] ssh invocations: %d (runs %d, channel opens %d)" % (cnt.total, cnt.runs, cnt.opens))
        self.assertEqual(base.shape(rem), base.shape(loc))
        self.assertIn(loc["verdict"], ("CONFIRMED_FAULT", "PROBABLE_FAULT", "FAULT"))
        self.assertLessEqual(cnt.total, MAX_SSH_PER_DIAGNOSE, rem["collection_impact"].get("remote_commands"))
        rc = rem["collection_impact"]["remote_commands"]
        self.assertEqual(rc["ssh_invocations"], cnt.total)
        self.assertGreater(rc["daemon_exchanges"], 20)
        self.assertNotIn("identity_elf_header", {k.split(":", 1)[1] for k in rc["by_purpose"]})
        self.assertTrue(rem["collection_impact"]["zero_stop"])

    def _adapter(self):
        cnt = Counter()
        ad = RemoteSshTargetAdapter(host="board.example", user="root", collector_path=self.collector,
                                    command_runner=cnt.runner, stream_opener=cnt.opener)
        self.addCleanup(ad.close)
        return ad, cnt

    def test_identity_verification_is_one_exchange_and_still_detects_change(self):
        proc, _binary, _ = self._launch("proc_thread_circular_deadlock.c", ready=False)
        ad, cnt = self._adapter()
        ident = ad.pin_target_identity(proc.pid)
        self.assertTrue(ident["start_time"] and ident["boot_id"] and ident["build_id"] and ident["pt_loads"])
        ad.read_memory(proc.pid, 0x400000, 4)            # opens the channel
        before_total, before_ex = cnt.total, ad.remote_command_summary()["daemon_exchanges"]
        for _ in range(20):
            ok, err = ad.verify_pinned_identity(proc.pid)
            self.assertTrue(ok, err)
        s = ad.remote_command_summary()
        self.assertEqual(cnt.total, before_total, "identity re-verification must not spawn ssh commands")
        self.assertEqual(s["daemon_exchanges"] - before_ex, 20, "exactly one daemon exchange per verification")
        # identity change through the adapter seam: start time, boot id, executable, binary fingerprint
        pinned = ad._pinned_identities[proc.pid]
        for field, value in (("start_time", "1"), ("boot_id", "other-boot"), ("executable", "/bin/other"),
                             ("exe_fingerprint", "1:2:3"), ("build_id", "00ff")):
            ad._pinned_identities[proc.pid] = dict(pinned, **{field: value})
            ok, err = ad.verify_pinned_identity(proc.pid)
            self.assertFalse(ok, field)
            self.assertIn("PID_REUSED", err)
            data, status, _ = ad.read_memory(proc.pid, 0x400000, 4)
            self.assertIsNone(data)
            self.assertEqual(status, "PID_REUSED")
        ad._pinned_identities[proc.pid] = dict(pinned)
        self.assertTrue(ad.verify_pinned_identity(proc.pid)[0])

    def test_exe_header_and_identity_are_cached_per_image(self):
        proc, _binary, _ = self._launch("proc_thread_circular_deadlock.c", ready=False)
        ad, cnt = self._adapter()
        first = ad.get_process_identity(proc.pid)
        bytes_first = ad.remote_command_summary()["bytes"]
        for _ in range(5):
            again = ad.get_process_identity(proc.pid)
            self.assertEqual(again["build_id"], first["build_id"])
            self.assertEqual(again["architecture"], first["architecture"])
            self.assertEqual(again["pt_loads"], first["pt_loads"])
        self.assertLess(ad.remote_command_summary()["bytes"] - bytes_first, 20000, "header re-transferred")
        self.assertEqual(ad.read_target_file(proc.pid, "/proc/%d/exe" % proc.pid, 65536)[:4], b"\x7fELF")
        self.assertLess(ad.remote_command_summary()["bytes"] - bytes_first, 20000)

    def test_maps_status_liveness_over_the_channel_match_procfs(self):
        proc, _binary, _ = self._launch("proc_thread_circular_deadlock.c", ready=False)
        ad, cnt = self._adapter()
        ad.get_process_identity(proc.pid)
        base_n = cnt.total
        maps = ad.get_proc_maps(proc.pid)
        with open("/proc/%d/maps" % proc.pid) as fh:
            want = [line.split()[0] for line in fh.read().splitlines()]
        self.assertEqual([m["start"][2:] + "-" + m["end"][2:] for m in maps], want)
        self.assertGreater(ad.get_process_status(proc.pid).get("Threads", 0), 2)
        self.assertEqual(ad.check_liveness(proc.pid), (True, None))
        self.assertEqual(ad.read_target_file(proc.pid, "/proc/%d/limits" % proc.pid, 8192)[:5], b"Limit")
        self.assertLessEqual(cnt.total - base_n, 1, "only the daemon open may cost an ssh command")
        proc.kill()
        proc.wait()
        self.assertFalse(ad.check_liveness(proc.pid)[0])

    def test_old_collector_without_ident_falls_back_to_one_shell_command(self):
        proc, _binary, _ = self._launch("proc_thread_circular_deadlock.c", ready=False)
        ad, cnt = self._adapter()
        ad._proc_cmds_unsupported_for = ad.collector_path           # as after UNKNOWN_COMMAND from a 1.2.x collector
        ident = ad.get_process_identity(proc.pid)
        self.assertTrue(ident["start_time"] and ident["boot_id"] and ident["build_id"])
        n = cnt.total
        ad.get_process_identity(proc.pid)
        self.assertEqual(cnt.total - n, 1, "identity without IDENT must be ONE ssh command, not four")


# the inherited IMP-006 tests are covered by their own module
for _name in [n for n in dir(base.RemoteDiagnoseTests) if n.startswith("test_")]:
    setattr(RemoteCommandCostTests, _name, None)


if __name__ == "__main__":
    unittest.main()
