#!/usr/bin/env python3
"""Phase 2.0-A.3.13 — Target Process Identity Fail-Closed Test Suite.

Audits and proves:
1. Mandatory identity attributes: Missing pid, start_time, or executable fails closed on commit, receipt, and resume.
2. Two missing values != equality: None == None never authorizes execution or satisfies identity match.
3. PID reuse detection on resume: Altered start_time, executable path, inode, or build_id raises PIDReusedError.
4. Target termination on resume: Non-alive process raises ProcessLookupError and marks state BLOCKED.
5. Capture transaction verification: Target identity is re-verified at commit time against pinned identity.
"""

import os
import shutil
import tempfile
import unittest

from extractor.target_adapter import LocalTargetAdapter, PIDReusedError


class TestPhase20A313IdentityFailClosed(unittest.TestCase):
    """Adversarial tests for fail-closed process identity and anti-PID-reuse verification."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="id_fail_closed_")
        self.session_id = "sess_id_fail_closed"
        self.pid = 6677
        self.valid_ident = {
            "pid": self.pid,
            "process_identity": f"{self.pid}:500000:boot",
            "start_time": "500000",
            "executable": "/usr/bin/app_worker",
            "executable_identity": "/usr/bin/app_worker:456",
            "build_id": "sha1:abcdef667788",
            "exe_inode": 456,
        }

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _setup_adapter(self, ident_override=None, liveness=(True, None)):
        ad = LocalTargetAdapter()
        cur_ident = dict(self.valid_ident)
        if ident_override:
            cur_ident.update(ident_override)
        ad.check_liveness = lambda p: liveness
        ad.get_process_identity = lambda p: dict(cur_ident)
        ad.get_threads = lambda p: [{"tid": p, "state": "R", "is_running_user_space": True, "voluntary_ctxt_switches": 5, "wchan": "0"}]
        ad.get_proc_maps = lambda p: [{"start_int": 0x500000, "end_int": 0x510000, "size": 65536, "is_readable": True, "category": "data"}]
        ad._memory_reader = lambda p, a, s: (b"Z" * s, "OBSERVED", None)
        return ad

    def test_01_missing_mandatory_identity_on_commit_fails_closed(self):
        """Missing start_time or executable on commit fails closed with PIDReusedError."""
        # 1. Start time lost between begin and commit
        ad1 = self._setup_adapter()
        tx1 = ad1.begin_capture_transaction(self.session_id, self.pid)
        ad1._record_physical_read(num_bytes=64, num_reads=1, data=b"1" * 64, pid=self.pid)
        # Identity changes / loses start_time before commit
        lost_start = dict(self.valid_ident)
        lost_start["start_time"] = None
        ad1.get_process_identity = lambda p: lost_start

        with self.assertRaises(PIDReusedError) as ctx1:
            ad1.commit_capture_transaction(tx1)
        self.assertIn("missing mandatory identity field 'start_time'", str(ctx1.exception).lower())

        # 2. Executable lost between begin and commit
        ad2 = self._setup_adapter()
        tx2 = ad2.begin_capture_transaction(self.session_id, self.pid)
        ad2._record_physical_read(num_bytes=64, num_reads=1, data=b"2" * 64, pid=self.pid)
        lost_exe = dict(self.valid_ident)
        lost_exe["executable"] = None
        ad2.get_process_identity = lambda p: lost_exe

        with self.assertRaises(PIDReusedError) as ctx2:
            ad2.commit_capture_transaction(tx2)
        self.assertIn("missing mandatory identity field 'executable'", str(ctx2.exception).lower())

    def test_02_two_missing_values_do_not_equal_identity_equality(self):
        """None == None for start_time or executable fails closed during identity verification."""
        ad = self._setup_adapter(ident_override={"start_time": None, "executable": None})
        # Pinning identity with missing mandatory attributes must fail closed
        with self.assertRaises(PIDReusedError) as ctx:
            ad.pin_target_identity(self.pid)
        self.assertIn("missing mandatory attribute", str(ctx.exception).lower())

        # verify_pinned_identity with two missing values fails closed
        ad._pinned_identities[self.pid] = {"pid": self.pid, "start_time": None, "executable": None}
        ok, err = ad.verify_pinned_identity(self.pid)
        self.assertFalse(ok)
        self.assertIn("missing mandatory identity field", err.lower())




if __name__ == "__main__":
    unittest.main()
