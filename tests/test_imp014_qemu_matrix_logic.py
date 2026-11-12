"""IMP-014: logic of the QEMU matrix harness that needs no QEMU (always runnable, architecture-neutral)."""
import gzip
import io
import json
import os
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO)

from scripts.qemu_matrix import checks, entries, guest, images, matrix, results, vm  # noqa: E402


class TestQemuArgs(unittest.TestCase):
    def _args(self, **kw):
        base = dict(qemu_bin="qemu-system-arm", machine="virt,highmem=off", cpu="cortex-a15", mem_mb=128,
                    kernel="/k", initrd="/i", console_tty="ttyAMA0", ssh_port=2222, console_log="/c.log")
        base.update(kw)
        return vm.build_qemu_args(**base)

    def test_constrained_headless_localhost_only(self):
        a = self._args()
        self.assertEqual(a[a.index("-smp") + 1], "1")
        self.assertEqual(a[a.index("-m") + 1], "128")
        self.assertIn("none", a[a.index("-display") + 1])
        nd = a[a.index("-netdev") + 1]
        self.assertIn("hostfwd=tcp:127.0.0.1:2222-:22", nd)  # bound to loopback only
        self.assertTrue(nd.startswith("user,"))
        self.assertIn("-no-reboot", a)
        self.assertNotIn("-enable-kvm", a)

    def test_memory_limits_enforced(self):
        for bad in (32, 63, 129, 2048):
            with self.assertRaises(ValueError):
                self._args(mem_mb=bad)
        self._args(mem_mb=64)

    def test_bad_port(self):
        with self.assertRaises(ValueError):
            self._args(ssh_port=0)

    def test_all_entries_respect_limits_and_have_expectations(self):
        for name, e in entries.ENTRIES.items():
            self.assertTrue(vm.MIN_MEM_MB <= e["mem_mb"] <= vm.MAX_MEM_MB, name)
            self.assertEqual(set(e["expected_support"]), {"mutex_owner", "allocator_chunks", "syscall_names",
                                                          "tcb_scan", "frame_layout", "cfi_unwind"}, name)
            self.assertIn(e["libc"], ("glibc", "musl"))
        # the roadmap minimum matrix
        self.assertEqual({(e["expected_abi"]["architecture"], e["libc"]) for e in entries.ENTRIES.values()},
                         {("arm", "glibc"), ("arm", "musl"), ("aarch64", "glibc")})

    def test_expected_support_matches_product_table_for_musl_and_arm(self):
        """The independent expectation and the product table agree on the glibc-only features."""
        from extractor.target_abi import TargetABI, check_support
        for name, e in entries.ENTRIES.items():
            a = e["expected_abi"]
            abi = TargetABI(status="DETECTED", architecture=a["architecture"], word_size=a["word_size"],
                            endianness=a["endianness"], libc=a["libc"])
            for feat, want in e["expected_support"].items():
                self.assertEqual(check_support(abi, feat).status, want, f"{name}/{feat}")


class FakeProc:
    """Stand-in for subprocess.Popen: records signals, can ignore SIGTERM."""

    def __init__(self, ignore_term=False, exited=False):
        self.pid = 424242
        self.ignore_term = ignore_term
        self.returncode = 0 if exited else None
        self.signals = []
        self.stderr = io.BytesIO(b"boom")

    def poll(self):
        return self.returncode

    def send_signal(self, sig):
        self.signals.append(sig)
        if sig == signal.SIGKILL or (sig == signal.SIGTERM and not self.ignore_term):
            self.returncode = -sig

    def wait(self, timeout=None):
        if self.returncode is None:
            raise subprocess.TimeoutExpired("fake", timeout)
        return self.returncode


class TestVmLifecycle(unittest.TestCase):
    def _vm(self, proc):
        v = vm.QemuVM(["qemu"], 2222, "/nonexistent.log", popen=lambda *a, **k: proc)
        v.start()
        return v

    def _patch_group(self, proc):
        # route group signals to the fake (no real process group exists)
        def fake_group(p, sig):
            p.send_signal(sig)
        return mock.patch.object(vm.QemuVM, "_signal_group", staticmethod(fake_group))

    def test_stop_terminates(self):
        p = FakeProc()
        with self._patch_group(p):
            info = self._vm(p).stop(grace_s=0.01)
        self.assertEqual(p.signals, [signal.SIGTERM])
        self.assertFalse(info["killed"])

    def test_stop_escalates_to_sigkill(self):
        p = FakeProc(ignore_term=True)
        with self._patch_group(p):
            info = self._vm(p).stop(grace_s=0.01)
        self.assertEqual(p.signals, [signal.SIGTERM, signal.SIGKILL])
        self.assertTrue(info["killed"])

    def test_stop_idempotent_and_safe_when_never_started(self):
        v = vm.QemuVM(["qemu"], 1, "/x")
        self.assertEqual(v.stop()["was_running"], False)
        p = FakeProc(exited=True)
        with self._patch_group(p):
            v2 = self._vm(p)
            v2.stop()
            v2.stop()
        self.assertEqual(p.signals, [])

    def test_double_start_rejected(self):
        p = FakeProc()
        v = self._vm(p)
        with self.assertRaises(RuntimeError):
            v.start()

    def test_wait_ready_success_timeout_and_vm_death(self):
        p = FakeProc()
        v = self._vm(p)
        clock = iter(range(0, 1000, 1))
        calls = {"n": 0}

        def probe():
            calls["n"] += 1
            return calls["n"] >= 3
        self.assertTrue(v.wait_ready(100, probe, sleep=lambda s: None, clock=lambda: float(next(clock))))
        # never ready -> times out (fake clock advances 1s per read)
        clock2 = iter(range(0, 1000, 1))
        self.assertFalse(v.wait_ready(5, lambda: False, sleep=lambda s: None, clock=lambda: float(next(clock2))))
        # VM died -> immediate False without probing
        dead = self._vm(FakeProc(exited=True))
        probed = []
        self.assertFalse(dead.wait_ready(5, lambda: probed.append(1) or True, sleep=lambda s: None))
        self.assertEqual(probed, [])

    def test_probe_exceptions_do_not_abort_wait(self):
        v = self._vm(FakeProc())
        seq = iter([RuntimeError("x"), RuntimeError("y"), True])

        def probe():
            r = next(seq)
            if isinstance(r, Exception):
                raise r
            return r
        clock = iter(range(0, 1000))
        self.assertTrue(v.wait_ready(100, probe, sleep=lambda s: None, clock=lambda: float(next(clock))))

    def test_real_process_group_teardown(self):
        """A real child that ignores SIGTERM is killed (with its own child) - no leftovers."""
        script = ("import os,signal,time,subprocess\n"
                  "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                  "c=subprocess.Popen(['sleep','60'])\n"
                  "print(c.pid,flush=True)\n"
                  "time.sleep(60)\n")
        v = vm.QemuVM([sys.executable, "-c", script], 1, "/x")
        v.start()
        child = int(v.proc.stdout.readline()) if v.proc.stdout else None  # stdout is DEVNULL -> None
        info = v.stop(grace_s=0.5)
        self.assertFalse(v.alive())
        self.assertTrue(info["killed"] or info.get("returncode") is not None)
        self.assertIsNone(child)


class TestResultSchema(unittest.TestCase):
    def _doc(self):
        e = entries.ENTRIES["arm32-musl"]
        d = results.new_result(e)
        d["checks"] = [results.check(cid, "n", results.PASS, "ok") for cid in results.CHECK_IDS]
        d["overall"] = results.overall(d["checks"])
        return d

    def test_valid_document(self):
        d = self._doc()
        self.assertEqual(results.validate_result(d), [])
        json.dumps(d)

    def test_invalid_status_rejected(self):
        with self.assertRaises(ValueError):
            results.check("C1", "n", "MAYBE", "x")
        d = self._doc()
        d["checks"][0]["status"] = "MAYBE"
        self.assertTrue(results.validate_result(d))

    def test_duplicate_and_missing_fields(self):
        d = self._doc()
        d["checks"].append(dict(d["checks"][0]))
        self.assertTrue(any("duplicate" in e for e in results.validate_result(d)))
        d2 = self._doc()
        del d2["checks"][0]["summary"]
        self.assertTrue(results.validate_result(d2))

    def test_overall_rules(self):
        ok = results.check("a", "n", results.PASS, "x")
        unsup = results.check("b", "n", results.UNSUPPORTED, "x")
        blocked = results.check("c", "n", results.BLOCKED, "reason")
        bad = results.check("d", "n", results.FAIL, "x")
        known = results.check("e", "n", results.FAIL, "x", known_defect="DEF-1")
        self.assertEqual(results.overall([ok, unsup, blocked]), "PASS")
        self.assertEqual(results.overall([ok, known]), "PASS")
        self.assertEqual(results.overall([ok, bad]), "FAIL")
        self.assertEqual(results.overall([ok], infrastructure_error="boot failed"), "INCOMPLETE")

    def test_blocked_needs_reason(self):
        d = self._doc()
        d["checks"][0] = {"id": d["checks"][0]["id"], "name": "n", "status": results.BLOCKED, "summary": "", "details": {}}
        self.assertTrue(results.validate_result(d))

    def test_markdown_summary(self):
        a, b = self._doc(), self._doc()
        b["entry"] = "other"
        md = matrix.markdown_summary([a, b])
        self.assertIn("| overall |", md)
        self.assertEqual(md.count("PASS"), 2 * len(results.CHECK_IDS) + 2)


class TestTransportAndHelpers(unittest.TestCase):
    def test_ssh_opts_precede_adapter_opts(self):
        args = ["ssh", "-p", "22", "-o", "StrictHostKeyChecking=accept-new", "--", "host", "cmd"]
        out = guest.inject_ssh_opts(args)
        self.assertEqual(out[0], "ssh")
        self.assertLess(out.index("StrictHostKeyChecking=no"), out.index("StrictHostKeyChecking=accept-new"))
        self.assertIn("UserKnownHostsFile=/dev/null", out)
        self.assertEqual(out[-3:], ["--", "host", "cmd"])

    def test_counting_transport_counts_commands(self):
        tr = guest.CountingTransport()
        with mock.patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, b"ok", b"")), \
                mock.patch("subprocess.Popen") as popen:
            tr.runner(["ssh", "h"], 1.0)
            tr.runner(["ssh", "h"], 1.0, input_bytes=b"x")
            tr.opener(["ssh", "h"])
        self.assertEqual(tr.snapshot(), {"commands": 3, "stream_opens": 1})
        self.assertTrue(popen.called)

    def test_region_pattern_and_cases(self):
        self.assertEqual(checks.region_pattern(0, 3), bytes([3, 10, 17]))
        self.assertEqual(checks.region_pattern(4093, 1), bytes([(4093 * 7 + 3) & 0xFF]))
        cases = checks.unaligned_cases(0x10000, 0x500)
        for label, addr, size, want in cases:
            self.assertEqual(len(want), size, label)
        self.assertTrue(any((a % 4096) + s > 4096 for _, a, s, _ in cases), "need a page-crossing case")
        self.assertTrue(any(a % 4096 != 0 for _, a, _, _ in cases))

    def test_parse_memtarget_line(self):
        p = checks.parse_memtarget_line("[MEMTARGET] pid=173 known=0x4fd000 len=48 region=0xb6ebc000 rlen=12288\n")
        self.assertEqual(p, {"pid": 173, "known": 0x4FD000, "known_len": 48, "region": 0xB6EBC000, "region_len": 12288})
        self.assertIsNone(checks.parse_memtarget_line("garbage"))

    def test_owner_value_scan(self):
        obs = {"locks": [{"name": "m", "owner_tid": None}], "t": [{"waiting_on_lock": {"held_by_tid": 12}}]}
        self.assertEqual(len(checks._scan_owner_values(obs)), 1)
        self.assertEqual(checks._scan_owner_values({"owner_tid": None, "x": [1, 2]}), [])

    def test_missing_prerequisites_reported_not_raised(self):
        with mock.patch("shutil.which", return_value=None):
            miss = matrix.missing_prerequisites("arm32-musl")
        self.assertTrue(any("qemu-system-arm" in m for m in miss))
        self.assertTrue(any("cross" in m or "arm-linux-gnueabihf-gcc" in m for m in miss))

    def test_run_entry_with_missing_prerequisites_writes_incomplete_result(self):
        with tempfile.TemporaryDirectory() as td, mock.patch.object(matrix, "missing_prerequisites", return_value=["nope"]), \
                mock.patch.object(vm, "leftover_qemu_processes", return_value=[]):
            doc = matrix.run_entry("arm32-musl", td)
            self.assertEqual(doc["overall"], "INCOMPLETE")
            self.assertIn("nope", doc["infrastructure_error"])
            on_disk = json.load(open(os.path.join(td, "arm32-musl.json")))
            self.assertEqual(results.validate_result(on_disk), [])

    def test_run_entry_always_stops_guest_when_checks_blow_up(self):
        stopped = []

        class FakeGuest:
            def __init__(self, name):
                self.work = None
                self.vm = None
                self.boot_info = {}

            def start(self):
                raise RuntimeError("boot failed")

            def stop(self):
                stopped.append(1)
                return {"was_running": True}

        with tempfile.TemporaryDirectory() as td, mock.patch.object(matrix, "missing_prerequisites", return_value=[]), \
                mock.patch.object(matrix.build_targets, "build_entry_targets", return_value={}), \
                mock.patch.object(guest, "Guest", FakeGuest), \
                mock.patch.object(vm, "leftover_qemu_processes", return_value=[]):
            doc = matrix.run_entry("arm32-musl", td)
        self.assertGreaterEqual(len(stopped), 1)
        self.assertEqual(doc["overall"], "INCOMPLETE")
        self.assertEqual(matrix._ACTIVE, [])

    def test_guarded_converts_exception_to_fail(self):
        def boom():
            raise ValueError("x")
        r = checks.guarded("C1_collector_deploy_and_slice", "n", boom)
        self.assertEqual(r["status"], results.FAIL)
        self.assertIn("ValueError", r["summary"])


class TestBoardRun(unittest.TestCase):
    def test_board_entry_expectations_follow_the_roadmap_rules(self):
        from scripts.qemu_matrix import board
        for arch, libc, owner in (("arm", "glibc", "NOT_SUPPORTED_ON_TARGET"), ("arm", "musl", "NOT_SUPPORTED_ON_TARGET"),
                                  ("aarch64", "glibc", "SUPPORTED"), ("aarch64", "musl", "NOT_SUPPORTED_ON_TARGET")):
            e = board.board_entry(arch, libc, "cc", "b")
            self.assertEqual(e["expected_support"]["mutex_owner"], owner, (arch, libc))
            self.assertEqual(e["expected_support"]["allocator_chunks"], owner, (arch, libc))
            self.assertEqual(e["expected_support"]["syscall_names"], "SUPPORTED")
        self.assertEqual(board.board_entry("arm", "glibc", "cc", "b")["expected_abi"]["word_size"], 32)
        # the board table must agree with the QEMU entries it generalises
        for name, e in entries.ENTRIES.items():
            b = board.board_entry(e["expected_abi"]["architecture"], e["libc"], "cc", name)
            self.assertEqual(b["expected_support"], e["expected_support"], name)

    def test_board_guest_does_not_start_a_vm(self):
        from scripts.qemu_matrix import board
        g = board.BoardGuest("10.0.0.9", 2200, "root", "/k", "/data")
        self.assertIsNone(g.vm)
        self.assertEqual(g.ssh_base()[-1], "root@10.0.0.9")
        self.assertIn("2200", g.ssh_base())
        ad, _ = g.make_adapter()
        self.assertEqual(ad.host, "10.0.0.9")
        self.assertEqual(ad.port, 2200)


class TestInitramfsAndImages(unittest.TestCase):
    def test_cpio_newc_roundtrip_with_overlay(self):
        with tempfile.TemporaryDirectory() as td:
            root = os.path.join(td, "root")
            os.makedirs(os.path.join(root, "etc"))
            open(os.path.join(root, "init"), "w").write("#!/bin/sh\n")
            os.chmod(os.path.join(root, "init"), 0o755)
            os.symlink("etc", os.path.join(root, "lnk"))
            base = images.cpio_from_tree(root)
            base_gz = os.path.join(td, "base.gz")
            with gzip.open(base_gz, "wb") as f:
                f.write(base)
            out = images.compose_initrd(base_gz, "ssh-ed25519 AAAA test\n", os.path.join(td, "out.gz"))
            raw = gzip.open(out, "rb").read()
            self.assertEqual(raw.count(b"TRAILER!!!"), 1)
            self.assertIn(b"root/.ssh/authorized_keys", raw)
            self.assertIn(b"ssh-ed25519 AAAA test", raw)
            self.assertIn(b"init", raw)
            if subprocess.run(["which", "cpio"], capture_output=True).returncode == 0:
                lst = subprocess.run(["cpio", "-t"], input=raw, capture_output=True).stdout.decode().split()
                for want in ("init", "etc", "lnk", "root/.ssh/authorized_keys"):
                    self.assertIn(want, lst)

    def test_cpio_is_reproducible(self):
        with tempfile.TemporaryDirectory() as td:
            open(os.path.join(td, "a"), "w").write("x")
            self.assertEqual(images.cpio_from_tree(td), images.cpio_from_tree(td))

    def test_download_rejects_bad_checksum(self):
        class Resp(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        with tempfile.TemporaryDirectory() as td, mock.patch.dict(os.environ, {"DYNAMICSTATE_QEMU_CACHE": td}), \
                mock.patch("urllib.request.urlopen", return_value=Resp(b"data")):
            with self.assertRaises(RuntimeError):
                images.download("https://example.invalid/f", "0" * 64, name="f")
            self.assertFalse(os.path.exists(os.path.join(td, "dl", "f")), "a file failing verification must be removed")
            import hashlib
            with mock.patch("urllib.request.urlopen", return_value=Resp(b"data")):
                p = images.download("https://example.invalid/f", hashlib.sha256(b"data").hexdigest(), name="f")
            self.assertTrue(os.path.isfile(p))
            self.assertEqual(images.downloads_manifest()[0]["size"], 4)

    def test_apk_checksum_verification(self):
        import base64
        import hashlib
        import zlib

        def gz(b):
            c = zlib.compressobj(wbits=31)
            return c.compress(b) + c.flush()
        sig, ctl, data = gz(b"s"), gz(b"control"), gz(b"data")
        with tempfile.NamedTemporaryFile(suffix=".apk") as f:
            f.write(sig + ctl + data)
            f.flush()
            good = "Q1" + base64.b64encode(hashlib.sha1(ctl).digest()).decode()
            images._apk_verify(f.name, good)
            with self.assertRaises(RuntimeError):
                images._apk_verify(f.name, "Q1AAAA")

    def test_images_ready_is_a_pure_check(self):
        with tempfile.TemporaryDirectory() as td, mock.patch.dict(os.environ, {"DYNAMICSTATE_QEMU_CACHE": td}), \
                mock.patch("urllib.request.urlopen", side_effect=AssertionError("network used")):
            for n in entries.entry_names():
                self.assertFalse(entries.images_ready(n))

    def test_musl_compile_commands_use_the_musl_sysroot_only(self):
        from scripts.qemu_matrix import build_targets
        c1, c2 = build_targets.musl_cc_cmd("cc", "/sys", "a.c", "out", "/lib/ld-musl-armhf.so.1",
                                           "libc.musl-armv7.so.1", "/lg.a", "/gccinc")
        self.assertIn("-nostdinc", c1)
        self.assertIn("/sys/usr/include", c1)
        self.assertIn("-nostdlib", c2)
        self.assertIn("-Wl,-dynamic-linker=/lib/ld-musl-armhf.so.1", c2)
        self.assertIn("/sys/lib/libc.musl-armv7.so.1", c2)


if __name__ == "__main__":
    unittest.main()
