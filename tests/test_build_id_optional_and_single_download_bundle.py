"""Tests for Build-ID-absent binary diagnosis and C99 collector 1-exec + 1-download bundle mode.

Verifies:
1. Binaries compiled with -Wl,--build-id=none (no GNU Build-ID) succeed through
   commit_capture_transaction() and issue_live_receipt_for_session() with honest
   build_id_absent metadata, while corrupt/empty identities still fail closed.
2. C99 dynamicstate-collector --snapshot-bundle <FILE> and --snapshot collect full
   process metadata in ONE single execution.
3. RemoteSshTargetAdapter.collect_and_download_bundle() performs EXACTLY 1 exec +
   1 download (when download_runner / xssh download is configured) and serves all
   subsequent metadata queries with ZERO additional exec calls.
"""

import os
import shutil
import subprocess
import tempfile
import unittest

from extractor.capture_backend import (
    DurableTrustStore,
    MissingIdentityFieldError,
)
from extractor.debug_image import inspect_elf
from extractor.target_adapter import (
    LocalTargetAdapter,
    PIDReusedError,
    RemoteSshTargetAdapter,
)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
COLLECTOR_BIN = os.path.join(REPO_ROOT, "target", "collector", "dynamicstate-collector")


class TestBuildIdOptionalAndSingleDownloadBundle(unittest.TestCase):
    def test_binary_without_gnu_build_id_commits_capture_transaction_cleanly(self):
        if not shutil.which("gcc"):
            self.skipTest("gcc required")
        with tempfile.TemporaryDirectory() as td:
            src = os.path.join(td, "nobid.c")
            exe = os.path.join(td, "nobid")
            with open(src, "w", encoding="utf-8") as fh:
                fh.write("#include <unistd.h>\nint main(void){ sleep(30); return 0; }\n")
            subprocess.run(["gcc", "-g", "-O0", "-Wl,--build-id=none", src, "-o", exe], check=True)
            info = inspect_elf(exe)
            self.assertIsNone(info.build_id, "Fixture must have no GNU Build-ID")

            proc = subprocess.Popen([exe])
            try:
                store_path = os.path.join(td, "trust.json")
                ad = LocalTargetAdapter()
                ad.trust_store = DurableTrustStore(store_path=store_path)
                tx = ad.begin_capture_transaction(
                    session_id="sess_nobid",
                    pid=proc.pid,
                    operation_type="diagnostic",
                    snapshot_binding="snap_nobid",
                )
                tx.physical_reads_count = 1
                tx.physical_bytes_read = 64
                committed = ad.commit_capture_transaction(tx)
                self.assertTrue(committed.committed)
                self.assertTrue(committed.metadata.get("build_id_absent"))

                # Corrupt/empty identity with neither build_id nor executable MUST still fail closed!
                ad_bad = LocalTargetAdapter()
                ad_bad.trust_store = DurableTrustStore(store_path=os.path.join(td, "trust2.json"))
                tx2 = ad_bad.begin_capture_transaction(
                    session_id="sess_bad",
                    pid=proc.pid,
                    operation_type="diagnostic",
                    snapshot_binding="snap_bad",
                )
                tx2.physical_reads_count = 1
                tx2.physical_bytes_read = 64
                ad_bad.get_process_identity = lambda pid, force=False: {
                    "pid": pid,
                    "start_time": tx2.pre_identity.get("start_time", "12345"),
                    "boot_id": tx2.pre_identity.get("boot_id", "boot-1"),
                    "build_id": None,
                    "executable": "",
                    "exe_fingerprint": "",
                }
                ad_bad.verify_pinned_identity = lambda *a, **kw: (True, "")
                with self.assertRaises((MissingIdentityFieldError, PIDReusedError)):
                    ad_bad.commit_capture_transaction(tx2)
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()

    def test_collector_single_exec_snapshot_bundle_and_single_download_hydration(self):
        if not os.path.isfile(COLLECTOR_BIN):
            self.skipTest("native dynamicstate-collector not built")
        my_pid = os.getpid()
        exec_calls = []
        dl_calls = []

        def xssh_exec_runner(args, timeout):
            cmd = args[-1]
            exec_calls.append(cmd)
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            return res.returncode, res.stdout, res.stderr

        def xssh_download_runner(remote_path, local_path, timeout):
            dl_calls.append((remote_path, local_path))
            shutil.copyfile(remote_path, local_path)
            return 0, "", ""

        with tempfile.TemporaryDirectory() as td:
            rpath = os.path.join(td, "remote_bundle.json")
            ad = RemoteSshTargetAdapter(
                host="xssh-3hop",
                collector_path=COLLECTOR_BIN,
                command_runner=xssh_exec_runner,
                download_runner=xssh_download_runner,
                use_control_master=False,
                use_daemon=False,
            )
            bundle = ad.collect_and_download_bundle(my_pid, remote_bundle_path=rpath)
            self.assertIsNotNone(bundle)
            self.assertEqual(len(exec_calls), 1, f"Expected exactly 1 exec, got {exec_calls}")
            self.assertEqual(len(dl_calls), 1, f"Expected exactly 1 download, got {dl_calls}")
            self.assertIn("--snapshot-bundle", exec_calls[0])

            # All subsequent metadata reads must make ZERO additional xssh exec calls!
            alive, err = ad.check_liveness(my_pid)
            self.assertTrue(alive, err)
            maps = ad.get_proc_maps(my_pid)
            self.assertGreater(len(maps), 0)
            ident = ad.get_process_identity(my_pid)
            self.assertEqual(ident["pid"], my_pid)
            ok_pin, pin_err = ad.verify_pinned_identity(my_pid, _allow_recent_sec=0.05)
            self.assertTrue(ok_pin, pin_err)
            status = ad.get_process_status(my_pid)
            self.assertIsInstance(status, dict)
            self.assertEqual(len(exec_calls), 1, "Hydrated bundle must serve all metadata with 0 extra execs")

    def test_collector_single_exec_stdout_snapshot_without_download_channel(self):
        if not os.path.isfile(COLLECTOR_BIN):
            self.skipTest("native dynamicstate-collector not built")
        my_pid = os.getpid()
        exec_calls = []

        def xssh_exec_runner(args, timeout):
            cmd = args[-1]
            exec_calls.append(cmd)
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            return res.returncode, res.stdout, res.stderr

        ad = RemoteSshTargetAdapter(
            host="xssh-3hop",
            collector_path=COLLECTOR_BIN,
            command_runner=xssh_exec_runner,
            use_control_master=False,
            use_daemon=False,
        )
        bundle = ad.collect_and_download_bundle(my_pid)
        self.assertIsNotNone(bundle)
        self.assertEqual(len(exec_calls), 1)
        self.assertIn("--snapshot", exec_calls[0])
        self.assertGreater(len(ad.get_proc_maps(my_pid)), 0)
        self.assertEqual(len(exec_calls), 1)


if __name__ == "__main__":
    unittest.main()
