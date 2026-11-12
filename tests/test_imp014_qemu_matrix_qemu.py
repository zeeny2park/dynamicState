"""IMP-014: the real QEMU matrix as a test (skipped unless QEMU, the cross compilers, the collector
binaries and the CACHED guest images are present).  Never downloads or builds images - run
``python3 -m scripts.qemu_matrix prepare`` first.  Each entry boots a TCG guest (minutes); restrict with
DYNAMICSTATE_QEMU_ENTRIES="aarch64-glibc".
"""
import os
import shutil
import sys
import tempfile
import unittest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO)

from scripts.qemu_matrix import checks, entries, matrix, results  # noqa: E402

_WANTED = [n.strip() for n in os.environ.get("DYNAMICSTATE_QEMU_ENTRIES", "").split(",") if n.strip()] or entries.entry_names()


def _skip_reason(name):
    miss = matrix.missing_prerequisites(name)
    return "; ".join(miss) if miss else None


class TestQemuMatrix(unittest.TestCase):
    docs = {}
    out_dir = None

    @classmethod
    def setUpClass(cls):
        cls.out_dir = tempfile.mkdtemp(prefix="qemu_matrix_test_")
        cls.addClassCleanup(shutil.rmtree, cls.out_dir, True)
        cls.host_ref = checks.host_reference()

    def _doc(self, name):
        reason = _skip_reason(name)
        if reason:
            self.skipTest(f"QEMU matrix entry {name} unavailable: {reason}")
        if name not in self.docs:
            self.docs[name] = matrix.run_entry(name, self.out_dir, host_ref=self.host_ref)
        d = self.docs[name]
        self.assertIsNone(d["infrastructure_error"], d["infrastructure_error"])
        self.assertEqual(results.validate_result(d), [])
        self.assertEqual(d["teardown"].get("leftover_qemu_processes"), [])
        return d

    def _status(self, doc, cid):
        return next(c for c in doc["checks"] if c["id"] == cid)

    def _common(self, name):
        d = self._doc(name)
        for cid in ("C1_collector_deploy_and_slice", "C2a_daemon_channel", "C2b_no_collector_fallback", "C3_abi_detection"):
            c = self._status(d, cid)
            self.assertEqual(c["status"], results.PASS, f"{cid}: {c['summary']}")
        return d

    @unittest.skipUnless("aarch64-glibc" in _WANTED, "entry not selected")
    def test_aarch64_glibc(self):
        d = self._common("aarch64-glibc")
        a = self._status(d, "C4a_deadlock_diagnosis")
        self.assertIn(a["status"], (results.PASS, results.BLOCKED), a["summary"])
        # heap walk on a remote glibc target is BLOCKED while HeapWalker cannot identify the remote glibc version
        self.assertIn(self._status(d, "C4b_glibc_only_gating")["status"], (results.PASS, results.BLOCKED))


if __name__ == "__main__":
    unittest.main()
