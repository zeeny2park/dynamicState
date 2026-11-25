"""Regression & parity tests for Unified Debug Image Identity Verification.

Verifies that DebugImageProvider and DebugArtifactProvider share the exact same
fail-closed verification contract for GNU Build IDs, .gnu_debuglink CRC-32,
independent SHA-256 fingerprints, and unverifiable identity evidence.
"""

import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from extractor.adapters.identity_policy import StrictBuildIdIdentityPolicy
from extractor.debug_artifacts import DebugArtifactProvider, compute_gnu_debuglink_crc
from extractor.debug_image import BinaryIdentity, DebugImageProvider, inspect_elf
from extractor.memory_snapshot import RawMemorySnapshot
from extractor.modules import RuntimeModule
from extractor.offline_analyzer import OfflineMemoryAnalyzer


class TestUnifiedDebugImageVerificationParity(unittest.TestCase):
    """Same input evidence must produce identical verification outcomes through both providers."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="unified_dbg_verify_")

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _compile_elf(self, name: str, code: str, build_id_flag: str = "-Wl,--build-id=none") -> str:
        src = os.path.join(self.tmp_dir, f"{name}.c")
        out = os.path.join(self.tmp_dir, name)
        with open(src, "w", encoding="utf-8") as fh:
            fh.write(code)
        subprocess.check_call(["gcc", "-g", "-O0", build_id_flag, src, "-o", out])
        return out

    def _run_both_providers(
        self,
        *,
        runtime_path: str,
        runtime_ident: BinaryIdentity,
        debug_path: str,
        debug_ident: BinaryIdentity,
        identity_policy=None,
    ):
        # 1. DebugImageProvider
        dip = DebugImageProvider(identity_policy=identity_policy)
        dip.debug_image_path = debug_path
        dip.debug_identity = debug_ident
        with mock.patch("extractor.debug_image.inspect_elf", return_value=runtime_ident):
            res_dip = dip.verify(runtime_path)

        # 2. DebugArtifactProvider
        dap = DebugArtifactProvider(identity_policy=identity_policy)
        if os.path.exists(debug_path):
            dap._ident_cache[os.path.abspath(debug_path)] = debug_ident
        mod = RuntimeModule(
            module_id="main",
            path=runtime_path,
            runtime_base=0x400000,
            runtime_end=0x401000,
            load_bias=0,
            build_id=runtime_ident.build_id,
            debuglink=runtime_ident.debuglink,
            architecture=runtime_ident.architecture,
            endianness=runtime_ident.endianness,
            elf_class=runtime_ident.elf_class,
        )
        res_dap = dap.verify(mod, debug_path)

        # Assert strict parity across both providers on canonical verification contract
        self.assertEqual(res_dip.compatible, res_dap.compatible)
        self.assertEqual(res_dip.verification_method, res_dap.verification_method)
        self.assertEqual(res_dip.verification_result, res_dap.verification_result)
        self.assertEqual(res_dip.verification_reason, res_dap.verification_reason)
        self.assertEqual(res_dip.identity_policy_id, res_dap.identity_policy_id)
        self.assertEqual(res_dip.identity_policy_version, res_dap.identity_policy_version)
        return res_dip, res_dap, dip

    def test_01_matching_real_build_ids_parity(self):
        dbg = os.path.join(self.tmp_dir, "real_match.debug")
        with open(dbg, "wb") as fh:
            fh.write(b"fake-debug")
        r_id = BinaryIdentity(path="/bin/app", elf_class="ELF64", architecture="x86_64", endianness="little", build_id="aa11bb22cc33", stripped=True)
        d_id = BinaryIdentity(path=dbg, elf_class="ELF64", architecture="x86_64", endianness="little", build_id="AA11BB22CC33", has_debug_info=True)
        res_dip, res_dap, dip = self._run_both_providers(runtime_path="/bin/app", runtime_ident=r_id, debug_path=dbg, debug_ident=d_id)
        self.assertTrue(res_dip.compatible)
        self.assertEqual(res_dip.verification_method, "gnu_build_id")
        self.assertEqual(res_dip.verification_result, "VERIFIED")
        self.assertEqual(res_dip.verification_reason, "BUILD_ID_MATCH")
        prov = dip.get_provenance()["debug_image"]
        self.assertEqual(prov["verification_method"], "gnu_build_id")
        self.assertEqual(prov["verification_result"], "VERIFIED")
        self.assertEqual(prov["verification_reason"], "BUILD_ID_MATCH")

    def test_02_different_real_build_ids_parity(self):
        dbg = os.path.join(self.tmp_dir, "real_diff.debug")
        with open(dbg, "wb") as fh:
            fh.write(b"fake-debug")
        r_id = BinaryIdentity(path="/bin/app", elf_class="ELF64", architecture="x86_64", endianness="little", build_id="1111aaaa", stripped=True)
        d_id = BinaryIdentity(path=dbg, elf_class="ELF64", architecture="x86_64", endianness="little", build_id="2222bbbb", has_debug_info=True)
        res_dip, _, _ = self._run_both_providers(runtime_path="/bin/app", runtime_ident=r_id, debug_path=dbg, debug_ident=d_id)
        self.assertFalse(res_dip.compatible)
        self.assertEqual(res_dip.verification_method, "gnu_build_id")
        self.assertEqual(res_dip.verification_result, "MISMATCH")
        self.assertEqual(res_dip.verification_reason, "BUILD_ID_MISMATCH")

    def test_03_missing_build_ids_matching_sha256_parity(self):
        bin_a = self._compile_elf("sha_same", "int v = 1; int main(void) { return v; }\n")
        dbg_copy = os.path.join(self.tmp_dir, "sha_same_copy.debug")
        shutil.copyfile(bin_a, dbg_copy)
        r_id = inspect_elf(bin_a)
        d_id = inspect_elf(dbg_copy)
        res_dip, _, dip = self._run_both_providers(runtime_path=bin_a, runtime_ident=r_id, debug_path=dbg_copy, debug_ident=d_id)
        self.assertTrue(res_dip.compatible)
        self.assertEqual(res_dip.verification_method, "sha256_fingerprint")
        self.assertEqual(res_dip.verification_result, "VERIFIED")
        self.assertEqual(res_dip.verification_reason, "FINGERPRINT_MATCH")
        self.assertEqual(dip.get_provenance()["debug_image"]["verification_method"], "sha256_fingerprint")

    def test_04_missing_build_ids_mismatched_sha256_parity(self):
        bin_a = self._compile_elf("sha_a", "int a = 1; int main(void) { return a; }\n")
        bin_b = self._compile_elf("sha_b", "int b = 2; int main(void) { return b; }\n")
        res_dip, _, _ = self._run_both_providers(
            runtime_path=bin_a,
            runtime_ident=inspect_elf(bin_a),
            debug_path=bin_b,
            debug_ident=inspect_elf(bin_b),
        )
        self.assertFalse(res_dip.compatible)
        self.assertEqual(res_dip.verification_method, "sha256_fingerprint")
        self.assertEqual(res_dip.verification_result, "MISMATCH")
        self.assertEqual(res_dip.verification_reason, "FINGERPRINT_MISMATCH")

    def test_05_missing_build_ids_no_fingerprints_parity(self):
        dbg = os.path.join(self.tmp_dir, "no_fp.debug")
        with open(dbg, "wb") as fh:
            fh.write(b"only-debug-exists")
        r_id = BinaryIdentity(path="/nonexistent/runtime", elf_class="ELF64", architecture="x86_64", endianness="little", build_id=None, stripped=True)
        d_id = BinaryIdentity(path=dbg, elf_class="ELF64", architecture="x86_64", endianness="little", build_id=None, has_debug_info=True)
        res_dip, _, _ = self._run_both_providers(runtime_path="/nonexistent/runtime", runtime_ident=r_id, debug_path=dbg, debug_ident=d_id)
        self.assertFalse(res_dip.compatible)
        self.assertEqual(res_dip.verification_method, "none")
        self.assertEqual(res_dip.verification_result, "UNVERIFIABLE")
        self.assertEqual(res_dip.verification_reason, "UNKNOWN_IDENTITY_UNVERIFIABLE")

    def test_06_matching_debuglink_filename_missing_crc_fails_closed_on_both(self):
        dbg = os.path.join(self.tmp_dir, "app.debug")
        with open(dbg, "wb") as fh:
            fh.write(b"debug-bytes-without-crc")
        r_id = BinaryIdentity(
            path="/nonexistent/app_stripped",
            elf_class="ELF64",
            architecture="x86_64",
            endianness="little",
            build_id=None,
            debuglink={"filename": "app.debug", "crc": None},  # Missing CRC!
            stripped=True,
        )
        d_id = BinaryIdentity(path=dbg, elf_class="ELF64", architecture="x86_64", endianness="little", build_id=None, has_debug_info=True)
        res_dip, _, dip = self._run_both_providers(runtime_path="/nonexistent/app_stripped", runtime_ident=r_id, debug_path=dbg, debug_ident=d_id)
        self.assertFalse(res_dip.compatible)
        self.assertEqual(res_dip.verification_method, "none")
        self.assertEqual(res_dip.verification_result, "UNVERIFIABLE")
        self.assertEqual(res_dip.verification_reason, "UNKNOWN_IDENTITY_UNVERIFIABLE")
        self.assertFalse(dip.get_provenance()["debug_image"]["verified"])

    def test_07_matching_debuglink_filename_incorrect_crc_rejected_on_both(self):
        dbg = os.path.join(self.tmp_dir, "app.debug")
        with open(dbg, "wb") as fh:
            fh.write(b"real-debug-payload-v1")
        wrong_crc = (compute_gnu_debuglink_crc(dbg) ^ 0xFFFFFFFF) & 0xFFFFFFFF
        r_id = BinaryIdentity(
            path="/nonexistent/app_stripped",
            elf_class="ELF64",
            architecture="x86_64",
            endianness="little",
            build_id=None,
            debuglink={"filename": "app.debug", "crc": wrong_crc},
            stripped=True,
        )
        d_id = BinaryIdentity(path=dbg, elf_class="ELF64", architecture="x86_64", endianness="little", build_id=None, has_debug_info=True)
        res_dip, _, _ = self._run_both_providers(runtime_path="/nonexistent/app_stripped", runtime_ident=r_id, debug_path=dbg, debug_ident=d_id)
        self.assertFalse(res_dip.compatible)
        self.assertEqual(res_dip.verification_method, "gnu_debuglink_crc32")
        self.assertEqual(res_dip.verification_result, "MISMATCH")
        self.assertEqual(res_dip.verification_reason, "DEBUGLINK_CRC_MISMATCH")

    def test_08_matching_debuglink_filename_valid_crc_verified_as_crc32_not_sha256(self):
        dbg = os.path.join(self.tmp_dir, "app.debug")
        with open(dbg, "wb") as fh:
            fh.write(b"real-debug-payload-v2")
        good_crc = compute_gnu_debuglink_crc(dbg)
        r_id = BinaryIdentity(
            path="/nonexistent/app_stripped",
            elf_class="ELF64",
            architecture="x86_64",
            endianness="little",
            build_id=None,
            debuglink={"filename": "app.debug", "crc": good_crc},
            stripped=True,
        )
        d_id = BinaryIdentity(path=dbg, elf_class="ELF64", architecture="x86_64", endianness="little", build_id=None, has_debug_info=True)
        res_dip, _, dip = self._run_both_providers(runtime_path="/nonexistent/app_stripped", runtime_ident=r_id, debug_path=dbg, debug_ident=d_id)
        self.assertTrue(res_dip.compatible)
        self.assertEqual(res_dip.verification_method, "gnu_debuglink_crc32")
        self.assertNotEqual(res_dip.verification_method, "sha256_fingerprint")
        self.assertEqual(res_dip.verification_result, "VERIFIED")
        self.assertEqual(res_dip.verification_reason, "COMPATIBLE_DEBUGLINK")
        prov = dip.get_provenance()["debug_image"]
        self.assertEqual(prov["verification_method"], "gnu_debuglink_crc32")
        self.assertEqual(prov["verification_result"], "VERIFIED")

        # StrictBuildIdIdentityPolicy still rejects debuglink when Build ID is absent
        res_strict, _, _ = self._run_both_providers(
            runtime_path="/nonexistent/app_stripped",
            runtime_ident=r_id,
            debug_path=dbg,
            debug_ident=d_id,
            identity_policy=StrictBuildIdIdentityPolicy(),
        )
        self.assertFalse(res_strict.compatible)
        self.assertEqual(res_strict.verification_reason, "STRICT_BUILD_ID_REQUIRED")

    def test_09_debuglink_filename_mismatch_fails_closed_on_both(self):
        dbg = os.path.join(self.tmp_dir, "wrong_name.debug")
        with open(dbg, "wb") as fh:
            fh.write(b"some-debug-bytes")
        good_crc = compute_gnu_debuglink_crc(dbg)
        r_id = BinaryIdentity(
            path="/nonexistent/app_stripped",
            elf_class="ELF64",
            architecture="x86_64",
            endianness="little",
            build_id=None,
            debuglink={"filename": "expected_app.debug", "crc": good_crc},
            stripped=True,
        )
        d_id = BinaryIdentity(path=dbg, elf_class="ELF64", architecture="x86_64", endianness="little", build_id=None, has_debug_info=True)
        res_dip, _, _ = self._run_both_providers(runtime_path="/nonexistent/app_stripped", runtime_ident=r_id, debug_path=dbg, debug_ident=d_id)
        self.assertFalse(res_dip.compatible)
        self.assertEqual(res_dip.verification_result, "UNVERIFIABLE")
        self.assertEqual(res_dip.verification_reason, "UNKNOWN_IDENTITY_UNVERIFIABLE")

    def test_10_missing_debug_artifact_rejected_on_both(self):
        missing = os.path.join(self.tmp_dir, "does_not_exist.debug")
        dap = DebugArtifactProvider()
        mod = RuntimeModule(
            module_id="main",
            path="/bin/app",
            runtime_base=0x1000,
            runtime_end=0x2000,
            load_bias=0,
            build_id=None,
            architecture="x86_64",
            endianness="little",
            elf_class="ELF64",
        )
        res_dap = dap.verify(mod, missing)
        self.assertFalse(res_dap.compatible)
        self.assertEqual(res_dap.reason, "DEBUG_IMAGE_NOT_FOUND")

        dip = DebugImageProvider()
        res_dip = dip.verify("/bin/app")
        self.assertFalse(res_dip.compatible)
        self.assertEqual(res_dip.reason, "DEBUG_IMAGE_NOT_LOADED")

    def test_11_offline_analyzer_rejects_missing_crc_and_bad_crc_debuglink(self):
        dbg = self._compile_elf("oa_dl.debug", "int k = 5; int main(void) { return k; }\n")
        ident = inspect_elf(dbg)
        wrong_crc = (compute_gnu_debuglink_crc(dbg) ^ 0x12345678) & 0xFFFFFFFF

        # Case A: matching filename + missing CRC -> DEBUG_IMAGE_UNVERIFIABLE
        snap_no_crc = RawMemorySnapshot(
            snapshot_id="snap_dl_no_crc",
            pid=101,
            binary="/nonexistent/oa_stripped",
            timestamp_ns=1,
            architecture=ident.architecture,
            endianness=ident.endianness,
            elf_class=ident.elf_class,
            maps=[],
            modules=[{
                "module_id": "main",
                "path": "/nonexistent/oa_stripped",
                "runtime_base": 0x400000,
                "runtime_end": 0x401000,
                "load_bias": 0,
                "build_id": None,
                "debuglink": {"filename": os.path.basename(dbg), "crc": None},
                "architecture": ident.architecture,
                "endianness": ident.endianness,
                "elf_class": ident.elf_class,
                "is_main_executable": True,
            }],
        )
        analyzer = OfflineMemoryAnalyzer()
        with self.assertRaises(ValueError) as ctx_a:
            analyzer.analyze(snap_no_crc, debug_image=dbg)
        self.assertIn("DEBUG_IMAGE_UNVERIFIABLE", str(ctx_a.exception))
        self.assertIn("UNKNOWN_IDENTITY_UNVERIFIABLE", str(ctx_a.exception))

        # Case B: matching filename + wrong CRC -> DEBUG_IMAGE_MISMATCH (DEBUGLINK_CRC_MISMATCH)
        snap_bad_crc = RawMemorySnapshot(
            snapshot_id="snap_dl_bad_crc",
            pid=102,
            binary="/nonexistent/oa_stripped",
            timestamp_ns=2,
            architecture=ident.architecture,
            endianness=ident.endianness,
            elf_class=ident.elf_class,
            maps=[],
            modules=[{
                "module_id": "main",
                "path": "/nonexistent/oa_stripped",
                "runtime_base": 0x400000,
                "runtime_end": 0x401000,
                "load_bias": 0,
                "build_id": None,
                "debuglink": {"filename": os.path.basename(dbg), "crc": wrong_crc},
                "architecture": ident.architecture,
                "endianness": ident.endianness,
                "elf_class": ident.elf_class,
                "is_main_executable": True,
            }],
        )
        with self.assertRaises(ValueError) as ctx_b:
            analyzer.analyze(snap_bad_crc, debug_image=dbg)
        self.assertIn("DEBUG_IMAGE_MISMATCH", str(ctx_b.exception))
        self.assertIn("DEBUGLINK_CRC_MISMATCH", str(ctx_b.exception))

    def test_12_gdb_symbol_file_never_loaded_after_failed_debuglink_verification(self):
        from extractor import extract_state

        dbg = self._compile_elf("gdb_dl.debug", "int m = 9; int main(void) { return m; }\n")
        ident = inspect_elf(dbg)
        fake_gdb = mock.MagicMock()
        fake_runtime = BinaryIdentity(
            path="/nonexistent/gdb_stripped",
            elf_class=ident.elf_class,
            architecture=ident.architecture,
            endianness=ident.endianness,
            build_id=None,
            debuglink={"filename": os.path.basename(dbg), "crc": None},  # Missing CRC!
            stripped=True,
        )
        real_inspect = inspect_elf

        def _selective_inspect(p):
            if os.path.abspath(p) == os.path.abspath(dbg):
                return real_inspect(p)
            return fake_runtime

        with mock.patch("extractor.extract_state.GdbBackend") as mock_backend_cls, \
             mock.patch("extractor.debug_image.inspect_elf", side_effect=_selective_inspect):
            mock_backend_cls.return_value.process_info.return_value = {"pid": 555, "binary": "/nonexistent/gdb_stripped"}
            with self.assertRaises(RuntimeError) as ctx:
                extract_state.snapshot(fake_gdb, debug_image=dbg)
            self.assertIn("DEBUG_IMAGE_INCOMPATIBLE", str(ctx.exception))
            self.assertIn("UNKNOWN_IDENTITY_UNVERIFIABLE", str(ctx.exception))
            fake_gdb.execute.assert_not_called()


if __name__ == "__main__":
    unittest.main()
