"""IMP-016: cross-architecture collector builds and SSH-stdin deployment.

Covers: `make dist` static multi-arch output, target-arch binary selection, stdin transfer of
>= 500KB binaries (real subprocess against a local path), noexec fallback location, and
version-mismatch redeploy.
"""

import os
import shutil
import struct
import subprocess
import tempfile
import unittest
from unittest import mock

from extractor import target_adapter
from extractor.debug_image import inspect_elf
from extractor.target_adapter import RemoteSshTargetAdapter

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
COLLECTOR_SRC = os.path.join(REPO_ROOT, "target", "collector")
CROSS = {
    "aarch64": "aarch64-linux-gnu-gcc",
    "x86_64": "x86_64-linux-gnu-gcc",
}


def fake_elf(machine: int, version: str, elf_class: int = 2, pad: int = 0) -> bytes:
    """Minimal ELF header with the collector version marker (never executed)."""
    if elf_class == 2:
        hdr = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\0" * 8 + struct.pack(
            "<HHIQQQIHHHHHH", 2, machine, 1, 0, 0, 0, 0, 64, 56, 0, 64, 0, 0)
    else:
        hdr = b"\x7fELF" + bytes([1, 1, 1, 0]) + b"\0" * 8 + struct.pack(
            "<HHIIIIIHHHHHH", 2, machine, 1, 0, 0, 0, 0, 52, 32, 0, 40, 0, 0)
    return hdr + b"DS_COLLECTOR_VERSION=" + version.encode() + b"\0" + b"\0" * pad


def copy_collector_tree(dst: str) -> str:
    out = os.path.join(dst, "collector")
    shutil.copytree(COLLECTOR_SRC, out, ignore=shutil.ignore_patterns("*.o", "dist", "dynamicstate-collector", "test_crypto"))
    return out


class FakeTarget:
    """Fake remote executor recording commands; optionally reports an arch and keeps stdin."""

    def __init__(self, uname="aarch64", present=None, noexec_prefixes=()):
        self.uname = uname
        self.present = dict(present or {})  # path -> version
        self.noexec_prefixes = noexec_prefixes
        self.uploads = []  # (cmd, bytes)
        self.cmds = []

    def __call__(self, args, timeout, input_bytes=None):
        cmd = args[-1]
        self.cmds.append(cmd)
        if "uname -m" in cmd:
            return 0, self.uname + "\n", ""
        if input_bytes is not None:
            self.uploads.append((cmd, input_bytes))
            if any(p in cmd for p in self.noexec_prefixes):
                return 1, "", "Permission denied (noexec)"
            return 0, "DEPLOY_OK\n", ""
        for path, ver in self.present.items():
            if f"'{path}'" in cmd or path in cmd:
                if "echo READY || echo MISSING" in cmd:
                    return 0, "READY\n", ""
                if "--version" in cmd:
                    return 0, f"dynamicstate-collector {ver}\n", ""
        return 0, "MISSING\n", ""


class SelectionAndVersionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        for arch, (machine, cls) in {"aarch64": (183, 2), "x86_64": (62, 2)}.items():
            d = os.path.join(self.tmp, "dist", arch)
            os.makedirs(d)
            with open(os.path.join(d, "dynamicstate-collector"), "wb") as f:
                f.write(fake_elf(machine, "1.2.3", cls))
        patcher = mock.patch.object(target_adapter, "COLLECTOR_DIR", self.tmp)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _adapter(self, target):
        return RemoteSshTargetAdapter(host="10.0.0.9", user="root", command_runner=target)

    def test_each_shipped_architecture_gets_its_own_binary_regardless_of_host_arch(self):
        for uname, expect in (("aarch64", "aarch64"), ("arm64", "aarch64"), ("x86_64", "x86_64"), ("amd64", "x86_64")):
            t = FakeTarget(uname=uname)
            res = self._adapter(t).ensure_remote_collector()
            self.assertEqual(res["status"], "DEPLOYED_BINARY", uname)
            self.assertEqual(res["architecture"], expect)
            self.assertTrue(res["local_binary"].endswith(os.path.join("dist", expect, "dynamicstate-collector")))
            self.assertEqual(t.uploads[0][1][18:20], struct.pack("<H", {"aarch64": 183, "x86_64": 62}[expect]))

    def test_target_without_a_shipped_binary_never_gets_a_wrong_architecture_binary(self):
        # 32-bit ARM is out of scope: no dist/arm binary ships.  The deploy must not substitute another
        # architecture's binary; it falls back to the shell path without uploading anything.
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "dist", "arm")))
        for uname in ("armv7l", "armv6l", "mips", "riscv64"):
            t = FakeTarget(uname=uname)
            res = self._adapter(t).ensure_remote_collector()
            self.assertEqual(res["status"], "FALLBACK_SHELL", uname)
            self.assertEqual(t.uploads, [], uname)
            self.assertIsNone(res.get("local_binary"), uname)

    def test_transfer_uses_stdin_not_argv(self):
        t = FakeTarget(uname="aarch64")
        self._adapter(t).ensure_remote_collector()
        cmd, payload = t.uploads[0]
        self.assertIn("cat >", cmd)
        self.assertNotIn("base64", cmd)
        self.assertLess(len(cmd), 1000)
        self.assertTrue(payload.startswith(b"\x7fELF"))

    def test_explicit_wrong_arch_binary_falls_back_to_shell(self):
        t = FakeTarget(uname="aarch64")
        x86 = os.path.join(self.tmp, "dist", "x86_64", "dynamicstate-collector")
        res = self._adapter(t).ensure_remote_collector(local_collector_bin=x86)
        self.assertEqual(res["status"], "FALLBACK_SHELL")
        self.assertEqual(t.uploads, [])

    def test_version_match_is_not_redeployed(self):
        t = FakeTarget(uname="aarch64", present={"/tmp/dynamicstate-collector": "1.2.3"})
        res = self._adapter(t).ensure_remote_collector()
        self.assertEqual(res["status"], "ALREADY_PRESENT")
        self.assertEqual(t.uploads, [])

    def test_version_mismatch_triggers_redeploy(self):
        t = FakeTarget(uname="aarch64", present={"/tmp/dynamicstate-collector": "0.9.0"})
        res = self._adapter(t).ensure_remote_collector()
        self.assertEqual(res["status"], "DEPLOYED_BINARY")
        self.assertEqual(res["collector_version"], "1.2.3")
        self.assertEqual(len(t.uploads), 1)

    def test_noexec_primary_location_uses_fallback(self):
        t = FakeTarget(uname="aarch64", noexec_prefixes=("cat > '/tmp/", "cat > /tmp/"))
        res = self._adapter(t).ensure_remote_collector()
        self.assertEqual(res["status"], "DEPLOYED_BINARY")
        self.assertEqual(res["collector_path"], "/var/tmp/dynamicstate-collector")
        self.assertEqual(len(t.uploads), 2)

    def test_configurable_destination(self):
        t = FakeTarget(uname="aarch64")
        res = self._adapter(t).ensure_remote_collector(remote_dest="/opt/ds/collector", fallback_dests=())
        self.assertEqual(res["collector_path"], "/opt/ds/collector")


@unittest.skipUnless(shutil.which("make") and shutil.which("cc"), "make/cc not available")
class RealLocalDeployTests(unittest.TestCase):
    """Executes the 'remote' commands for real via `sh -c`, with real stdin transfer."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.src = copy_collector_tree(cls.tmp)
        cls.bins = {}
        for ver in ("1.0.0", "2.0.0"):
            d = os.path.join(cls.tmp, "build-" + ver)
            shutil.copytree(cls.src, d)
            r = subprocess.run(["make", "-C", d, f"VERSION={ver}", "dynamicstate-collector"], capture_output=True, text=True)
            if r.returncode != 0:
                raise unittest.SkipTest("native collector build failed: " + r.stderr[-300:])
            cls.bins[ver] = os.path.join(d, "dynamicstate-collector")
        # >= 500KB variant of v2 (ELF tolerates trailing data).
        cls.big = os.path.join(cls.tmp, "collector-big")
        shutil.copy(cls.bins["2.0.0"], cls.big)
        with open(cls.big, "ab") as f:
            f.write(b"\0" * (600 * 1024))
        os.chmod(cls.big, 0o755)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    @staticmethod
    def _local_sh(args, timeout, input_bytes=None):
        res = subprocess.run(["sh", "-c", args[-1]], input=input_bytes, capture_output=True, timeout=timeout)
        return res.returncode, res.stdout.decode(), res.stderr.decode()

    def _adapter(self):
        return RemoteSshTargetAdapter(host="localhost", user="x", command_runner=self._local_sh)

    def test_collector_reports_version(self):
        out = subprocess.run([self.bins["2.0.0"], "--version"], capture_output=True, text=True)
        self.assertEqual(out.stdout.strip(), "dynamicstate-collector 2.0.0")

    def test_large_binary_deploys_over_stdin_then_version_mismatch_redeploys(self):
        dest = os.path.join(self.tmp, "remote", "collector")
        os.makedirs(os.path.dirname(dest))
        # Pre-deploy old version.
        r1 = self._adapter().ensure_remote_collector(local_collector_bin=self.bins["1.0.0"], remote_dest=dest, fallback_dests=())
        self.assertEqual(r1["status"], "DEPLOYED_BINARY", r1)
        # Same version again -> not redeployed.
        r1b = self._adapter().ensure_remote_collector(local_collector_bin=self.bins["1.0.0"], remote_dest=dest, fallback_dests=())
        self.assertEqual(r1b["status"], "ALREADY_PRESENT")
        # New (>=500KB) version -> mismatch -> redeploy via stdin.
        self.assertGreaterEqual(os.path.getsize(self.big), 500 * 1024)
        r2 = self._adapter().ensure_remote_collector(local_collector_bin=self.big, remote_dest=dest, fallback_dests=())
        self.assertEqual(r2["status"], "DEPLOYED_BINARY", r2)
        self.assertEqual(r2["bytes_transferred"], os.path.getsize(self.big))
        self.assertEqual(os.path.getsize(dest), os.path.getsize(self.big))
        out = subprocess.run([dest, "--version"], capture_output=True, text=True)
        self.assertEqual(out.stdout.strip(), "dynamicstate-collector 2.0.0")

    def test_unusable_primary_location_falls_back(self):
        bad = os.path.join(self.tmp, "does-not-exist-dir", "collector")
        good = os.path.join(self.tmp, "fallback-collector")
        res = self._adapter().ensure_remote_collector(
            local_collector_bin=self.bins["1.0.0"], remote_dest=bad, fallback_dests=(good,))
        self.assertEqual(res["status"], "DEPLOYED_BINARY", res)
        self.assertEqual(res["collector_path"], good)


class MakeDistTests(unittest.TestCase):
    def test_make_dist_builds_static_binaries(self):
        if not shutil.which("make"):
            self.skipTest("make not installed")
        available = [a for a, cc in CROSS.items() if shutil.which(cc)]
        missing = {a: cc for a, cc in CROSS.items() if a not in available}
        if len(available) < 1:
            self.skipTest(f"no cross compilers installed: {sorted(missing.values())}")
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        src = copy_collector_tree(tmp)
        res = subprocess.run(["make", "-C", src, "dist"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("SKIPPED", res.stdout)
        expected_machine = {"aarch64": "aarch64", "x86_64": "x86_64"}
        for arch in available:
            path = os.path.join(src, "dist", arch, "dynamicstate-collector")
            self.assertTrue(os.path.isfile(path), f"missing {path}")
            self.assertEqual(inspect_elf(path).architecture, expected_machine[arch])
            with open(path, "rb") as f:
                data = f.read()
            self.assertIn(b"DS_COLLECTOR_VERSION=", data)
            # Static: no PT_INTERP / PT_DYNAMIC program header.
            ph = subprocess.run(["readelf", "-lW", path], capture_output=True, text=True) if shutil.which("readelf") else None
            if ph is not None:
                self.assertNotIn("INTERP", ph.stdout)
                self.assertNotIn("DYNAMIC", ph.stdout)
        for arch in missing:
            self.assertFalse(os.path.exists(os.path.join(src, "dist", arch)))
            self.assertIn(missing[arch], res.stdout)
        if len(available) < 2:
            self.skipTest(f"only {available} cross compilers present; need both in-scope architectures (aarch64, x86_64)")


if __name__ == "__main__":
    unittest.main()
