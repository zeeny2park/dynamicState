"""Regression & integration tests for Debug Image Identity Fail-Closed contract
and Custom Remote Adapter contract boundaries.
"""

import hashlib
import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from extractor.adapters.identity_policy import (
    DEFAULT_IDENTITY_POLICY,
    DefaultTargetIdentityPolicy,
    StrictBuildIdIdentityPolicy,
    normalize_sha256_fingerprint,
)
from extractor.adapters.registry import TargetAdapterRegistry, TransportFieldSpec, TransportMetadata
from extractor.debug_artifacts import DebugArtifactProvider
from extractor.debug_image import BinaryIdentity, DebugImageProvider, compute_elf_sha256, inspect_elf
from extractor.modules import RuntimeModule
from extractor.target_adapter import TargetExecutionAdapter


_FP_A = "sha256:" + ("a" * 64)
_FP_B = "sha256:" + ("b" * 64)


class TestIdentityPolicyDebugCompatibilityMatrix(unittest.TestCase):
    """Verify DefaultTargetIdentityPolicy & StrictBuildIdIdentityPolicy truth table."""

    def setUp(self):
        self.default_pol = DefaultTargetIdentityPolicy()
        self.strict_pol = StrictBuildIdIdentityPolicy()

    def test_matching_real_build_ids(self):
        ok, reason = self.default_pol.validate_debug_image_compatibility("deadbeef1234", "DEADBEEF1234")
        self.assertTrue(ok)
        self.assertEqual(reason, "BUILD_ID_MATCH")

        ok_s, reason_s = self.strict_pol.validate_debug_image_compatibility("deadbeef1234", "deadbeef1234")
        self.assertTrue(ok_s)
        self.assertEqual(reason_s, "BUILD_ID_MATCH")

    def test_different_real_build_ids(self):
        ok, reason = self.default_pol.validate_debug_image_compatibility("deadbeef1111", "deadbeef2222")
        self.assertFalse(ok)
        self.assertEqual(reason, "BUILD_ID_MISMATCH")

        ok_s, reason_s = self.strict_pol.validate_debug_image_compatibility("deadbeef1111", "deadbeef2222")
        self.assertFalse(ok_s)
        self.assertEqual(reason_s, "BUILD_ID_MISMATCH")

    def test_both_missing_build_ids_fail_closed_without_fingerprints(self):
        for rb, db in ((None, None), ("", ""), ("default_build_id", None)):
            ok, reason = self.default_pol.validate_debug_image_compatibility(rb, db)
            self.assertFalse(ok)
            self.assertEqual(reason, "UNKNOWN_IDENTITY_UNVERIFIABLE")

    def test_both_synthetic_build_ids_without_fingerprints_fail_closed(self):
        # Even identical synthetic markers MUST NOT establish debug image compatibility
        ok, reason = self.default_pol.validate_debug_image_compatibility(
            "no-build-id:0123456789abcdef01234567",
            "no-build-id:0123456789abcdef01234567",
        )
        self.assertFalse(ok)
        self.assertEqual(reason, "UNKNOWN_IDENTITY_UNVERIFIABLE")

    def test_both_synthetic_with_different_fingerprints_rejected(self):
        ok, reason = self.default_pol.validate_debug_image_compatibility(
            "no-build-id:0123456789abcdef01234567",
            "no-build-id:0123456789abcdef01234567",
            runtime_fingerprint=_FP_A,
            debug_fingerprint=_FP_B,
        )
        self.assertFalse(ok)
        self.assertEqual(reason, "FINGERPRINT_MISMATCH")

    def test_both_synthetic_with_matching_verified_sha256_fingerprints(self):
        ok, reason = self.default_pol.validate_debug_image_compatibility(
            "no-build-id:0123456789abcdef01234567",
            "no-build-id:fedcba9876543210fedcba98",
            runtime_fingerprint=_FP_A,
            debug_fingerprint=_FP_A,
        )
        self.assertTrue(ok)
        self.assertEqual(reason, "FINGERPRINT_MATCH")

    def test_non_cryptographic_path_like_fingerprints_rejected(self):
        # Matching file paths must never be accepted as cryptographic fingerprints
        self.assertIsNone(normalize_sha256_fingerprint("/usr/bin/app"))
        self.assertIsNone(normalize_sha256_fingerprint("sha256:not-a-valid-hex"))
        ok, reason = self.default_pol.validate_debug_image_compatibility(
            None,
            None,
            runtime_fingerprint="/usr/bin/app",
            debug_fingerprint="/usr/bin/app",
        )
        self.assertFalse(ok)
        self.assertEqual(reason, "UNKNOWN_IDENTITY_UNVERIFIABLE")

    def test_one_missing_and_one_real_build_id(self):
        ok1, r1 = self.default_pol.validate_debug_image_compatibility("abcd1234", None)
        self.assertFalse(ok1)
        self.assertEqual(r1, "BUILD_ID_NOT_AVAILABLE")

        ok2, r2 = self.default_pol.validate_debug_image_compatibility(None, "abcd1234")
        self.assertFalse(ok2)
        self.assertEqual(r2, "BUILD_ID_NOT_AVAILABLE")

        ok3, r3 = self.default_pol.validate_debug_image_compatibility("no-build-id:1111", "abcd1234")
        self.assertFalse(ok3)
        self.assertEqual(r3, "BUILD_ID_NOT_AVAILABLE")

    def test_strict_policy_rejects_absent_or_synthetic_even_with_matching_fingerprints(self):
        ok, reason = self.strict_pol.validate_debug_image_compatibility(
            None,
            None,
            runtime_fingerprint=_FP_A,
            debug_fingerprint=_FP_A,
        )
        self.assertFalse(ok)
        self.assertEqual(reason, "STRICT_BUILD_ID_REQUIRED")

        ok2, reason2 = self.strict_pol.validate_debug_image_compatibility(
            "no-build-id:aaaa",
            "no-build-id:aaaa",
            runtime_fingerprint=_FP_A,
            debug_fingerprint=_FP_A,
        )
        self.assertFalse(ok2)
        self.assertEqual(reason2, "STRICT_BUILD_ID_REQUIRED")

    def test_runtime_capture_without_build_id_still_supported_by_default_policy(self):
        bid, err = self.default_pol.resolve_build_id(
            {"executable": "/opt/embedded/app", "exe_fingerprint": "1234:5678"},
            {},
        )
        self.assertIsNone(err)
        self.assertTrue(bid.startswith("no-build-id:"))


class TestDebugImageAndArtifactCallersFailClosed(unittest.TestCase):
    """Verify DebugImageProvider, DebugArtifactProvider, extract_state, and OfflineAnalyzer."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="dbg_id_fail_closed_")

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _compile_elf(self, name: str, code: str, build_id_flag: str = "-Wl,--build-id=none") -> str:
        src = os.path.join(self.tmp_dir, f"{name}.c")
        out = os.path.join(self.tmp_dir, name)
        with open(src, "w", encoding="utf-8") as fh:
            fh.write(code)
        subprocess.check_call(["gcc", "-g", "-O0", build_id_flag, src, "-o", out])
        return out

    def test_two_different_no_build_id_elfs_rejected_by_debug_image_provider(self):
        bin_a = self._compile_elf("app_a", "int g_a = 1; int main(void) { return g_a; }\n")
        bin_b = self._compile_elf("app_b", "int g_b = 2; int main(void) { return g_b; }\n")
        self.assertIsNone(inspect_elf(bin_a).build_id)
        self.assertIsNone(inspect_elf(bin_b).build_id)

        prov = DebugImageProvider(bin_b)
        compat = prov.verify(bin_a)
        self.assertFalse(compat.compatible)
        self.assertEqual(compat.reason, "FINGERPRINT_MISMATCH")

        # Provenance must accurately record verified=False, compatible=False
        prov_meta = prov.get_provenance()
        self.assertFalse(prov_meta["debug_image"]["verified"])
        self.assertFalse(prov_meta["debug_image"]["compatible"])
        self.assertEqual(prov_meta["debug_image"]["reason"], "FINGERPRINT_MISMATCH")
        self.assertEqual(prov_meta["debug_image"]["identity_policy_id"], "default-optional-build-id")

    def test_identical_no_build_id_elf_copy_accepted_by_fingerprint_not_path(self):
        bin_a = self._compile_elf("app_same", "int g = 7; int main(void) { return g; }\n")
        bin_copy = os.path.join(self.tmp_dir, "subdir_copy.debug")
        shutil.copyfile(bin_a, bin_copy)
        self.assertNotEqual(os.path.realpath(bin_a), os.path.realpath(bin_copy))

        prov = DebugImageProvider(bin_copy)
        compat = prov.verify(bin_a)
        self.assertTrue(compat.compatible)
        self.assertEqual(compat.reason, "FINGERPRINT_MATCH")

        # Strict policy still rejects even byte-identical no-build-id ELF
        strict_prov = DebugImageProvider(bin_copy, identity_policy=StrictBuildIdIdentityPolicy())
        compat_strict = strict_prov.verify(bin_a)
        self.assertFalse(compat_strict.compatible)
        self.assertEqual(compat_strict.reason, "STRICT_BUILD_ID_REQUIRED")

    def test_unreadable_mock_paths_with_absent_build_ids_return_unknown_unverifiable(self):
        prov = DebugImageProvider()
        prov.debug_image_path = "/nonexistent/debug.elf"
        prov.debug_identity = BinaryIdentity(
            path="/nonexistent/debug.elf",
            elf_class="ELF64",
            architecture="x86_64",
            endianness="little",
            build_id=None,
            has_debug_info=True,
        )
        fake_runtime = BinaryIdentity(
            path="/nonexistent/runtime.elf",
            elf_class="ELF64",
            architecture="x86_64",
            endianness="little",
            build_id=None,
            stripped=True,
        )
        with mock.patch("extractor.debug_image.inspect_elf", return_value=fake_runtime):
            compat = prov.verify("/nonexistent/runtime.elf")
        self.assertFalse(compat.compatible)
        self.assertEqual(compat.reason, "UNKNOWN_IDENTITY_UNVERIFIABLE")

    def test_debug_artifact_provider_closes_missing_module_build_id_fail_open(self):
        bin_a = self._compile_elf("art_a", "int x = 10; int main(void) { return x; }\n")
        bin_b = self._compile_elf("art_b", "int y = 20; int main(void) { return y; }\n")
        provider = DebugArtifactProvider()

        ident_a = inspect_elf(bin_a)
        mod_a = RuntimeModule(
            module_id="main",
            path=bin_a,
            runtime_base=0x1000,
            runtime_end=0x2000,
            load_bias=0,
            build_id=None,
            architecture=ident_a.architecture,
            endianness=ident_a.endianness,
            elf_class=ident_a.elf_class,
        )
        # Different no-build-id debug binary must FAIL CLOSED
        compat_diff = provider.verify(mod_a, bin_b)
        self.assertFalse(compat_diff.compatible)
        self.assertEqual(compat_diff.reason, "FINGERPRINT_MISMATCH")

        # Same no-build-id binary matches via SHA-256 fingerprint
        compat_same = provider.verify(mod_a, bin_a)
        self.assertTrue(compat_same.compatible)
        self.assertEqual(compat_same.reason, "FINGERPRINT_MATCH")

        # Unreadable module path + missing build ID -> UNKNOWN_IDENTITY_UNVERIFIABLE
        mod_unreadable = RuntimeModule(
            module_id="main",
            path="/nonexistent/mod_a",
            runtime_base=0x1000,
            runtime_end=0x2000,
            load_bias=0,
            build_id=None,
            architecture=ident_a.architecture,
            endianness=ident_a.endianness,
            elf_class=ident_a.elf_class,
        )
        compat_unk = provider.verify(mod_unreadable, bin_b)
        self.assertFalse(compat_unk.compatible)
        self.assertEqual(compat_unk.reason, "UNKNOWN_IDENTITY_UNVERIFIABLE")

    def test_extract_state_blocks_symbol_file_load_when_unverifiable(self):
        from extractor import extract_state

        bin_a = self._compile_elf("es_a", "int a = 1; int main(void) { return a; }\n")
        bin_b = self._compile_elf("es_b", "int b = 2; int main(void) { return b; }\n")
        fake_gdb = mock.MagicMock()

        with mock.patch("extractor.extract_state.GdbBackend") as mock_backend_cls:
            mock_backend_cls.return_value.process_info.return_value = {"pid": 123, "binary": bin_a}
            with self.assertRaises(RuntimeError) as ctx:
                extract_state.snapshot(fake_gdb, debug_image=bin_b)
            self.assertIn("DEBUG_IMAGE_INCOMPATIBLE", str(ctx.exception))
            self.assertIn("FINGERPRINT_MISMATCH", str(ctx.exception))
            # GDB symbol-file must NEVER have been executed
            fake_gdb.execute.assert_not_called()

    def test_offline_analyzer_distinguishes_unverifiable_from_mismatch(self):
        from extractor.offline_analyzer import OfflineMemoryAnalyzer
        from extractor.memory_snapshot import RawMemorySnapshot

        bin_b = self._compile_elf("oa_b", "int z = 3; int main(void) { return z; }\n")
        ident_b = inspect_elf(bin_b)
        raw_snap = RawMemorySnapshot(
            snapshot_id="snap_unverifiable_1",
            pid=999,
            binary="/nonexistent/runtime_no_bid",
            timestamp_ns=1,
            architecture=ident_b.architecture,
            endianness=ident_b.endianness,
            elf_class=ident_b.elf_class,
            maps=[],
            modules=[
                {
                    "module_id": "main",
                    "path": "/nonexistent/runtime_no_bid",
                    "runtime_base": 0x400000,
                    "runtime_end": 0x401000,
                    "load_bias": 0,
                    "build_id": None,
                    "architecture": ident_b.architecture,
                    "endianness": ident_b.endianness,
                    "elf_class": ident_b.elf_class,
                    "is_main_executable": True,
                }
            ],
        )
        analyzer = OfflineMemoryAnalyzer()
        with self.assertRaises(ValueError) as ctx:
            analyzer.analyze(raw_snap, debug_image=bin_b)
        self.assertIn("DEBUG_IMAGE_UNVERIFIABLE", str(ctx.exception))
        self.assertIn("UNKNOWN_IDENTITY_UNVERIFIABLE", str(ctx.exception))


class _PureCustomRemoteAdapter(TargetExecutionAdapter):
    """Standalone custom remote adapter (NOT subclassing LocalTargetAdapter or RemoteSshTargetAdapter)."""

    def __init__(self, endpoint: str, token: str = ""):
        super().__init__()
        self.endpoint = endpoint
        self.token = token
        self._policy = StrictBuildIdIdentityPolicy()

    def is_remote(self) -> bool:
        return True

    def get_identity_policy(self):
        return self._policy

    def get_target_info(self):
        return {"transport": "customrpc", "endpoint": self.endpoint, "remote": True}

    def list_processes(self):
        return [{"pid": 4242, "comm": "remote_svc"}]

    def get_process_status(self, pid: int):
        return {"pid": pid, "Name": "remote_svc", "VmRSS": "12000 kB", "Threads": "1"}

    def get_process_identity(self, pid: int, force: bool = False):
        return {
            "pid": pid,
            "start_time": 123456,
            "boot_id": "remote-boot-uuid-1",
            "executable": "/opt/remote/remote_svc",
            "executable_identity": "dev1:ino99",
            "build_id": "0123456789abcdef0123456789abcdef01234567",
            "process_identity": f"{pid}:123456:remote-boot-uuid-1",
        }

    def get_memory_maps(self, pid: int):
        return [{"start": 0x400000, "end": 0x401000, "perms": "r-xp", "pathname": "/opt/remote/remote_svc"}]

    def list_threads(self, pid: int):
        return [{"tid": pid, "name": "remote_svc", "state": "S"}]

    def target_host(self) -> str:
        return self.endpoint

    def check_liveness(self, pid: int):
        return (True, None) if int(pid) == 4242 else (False, 'not_found')

    def get_proc_maps(self, pid: int):
        return self.get_memory_maps(pid)

    def get_threads(self, pid: int):
        return self.list_threads(pid)

    def read_file(self, path: str, max_bytes: int = 1048576):
        return b""

    def read_memory(self, pid: int, address: int, size: int) -> bytes:
        return b"\x00" * size


class TestCustomRemoteAdapterContract(unittest.TestCase):
    """Section 4: Verify pure custom remote adapter registry dispatch & capture transaction lifecycle."""

    def test_custom_remote_registry_dispatch_and_capture_transaction_lifecycle(self):
        reg = TargetAdapterRegistry()
        reg.register(
            transport_id="customrpc",
            uri_schemes=("customrpc",),
            factory=lambda params: _PureCustomRemoteAdapter(
                endpoint=params["endpoint"],
                token=params.get("token", ""),
            ),
            uri_to_params=lambda parsed: {
                "endpoint": f"{parsed.host}:{parsed.port or 9000}",
                "token": parsed.query.get("token", ""),
            },
            metadata=TransportMetadata(
                id="customrpc",
                label_en="Custom RPC Remote",
                label_ko="Custom RPC 원격",
                is_remote=True,
                uri_schemes=("customrpc",),
                fields=(
                    TransportFieldSpec(name="endpoint", label_en="Endpoint", label_ko="엔드포인트", required=True),
                    TransportFieldSpec(name="token", label_en="API Token", label_ko="API 토큰", required=False, secret=True),
                ),
            ),
        )
        # 1. Registry / URI dispatch verification
        uri = "customrpc://rpc-node.internal:9443?token=supersecret"
        adapter = reg.dispatch(uri)
        self.assertIsInstance(adapter, _PureCustomRemoteAdapter)
        self.assertTrue(adapter.is_remote())
        self.assertIsInstance(adapter.get_identity_policy(), StrictBuildIdIdentityPolicy)

        # Redaction check: secret field never leaks in describe() output
        desc = reg.describe(uri)
        self.assertNotIn("supersecret", str(desc))

        # 2. Adapter capture lifecycle verification (transaction + receipt + policy provenance)
        from extractor.capture_backend import DurableTrustStore
        with tempfile.TemporaryDirectory() as tmp:
            ts = DurableTrustStore(os.path.join(tmp, "trust_store.json"))
            adapter.trust_store = ts
            tx = adapter.begin_capture_transaction(
                session_id="sess_custom_remote_1",
                pid=4242,
                operation_type="diagnostic",
                require_lifecycle_persistence=False,
            )
            data = adapter.read_memory(4242, 0x400000, 16)
            self.assertEqual(len(data), 16)
            tx.physical_bytes_read = len(data)
            tx.physical_reads_count = 1
            tx.read_operations.append({
                "address": 0x400000,
                "requested_size": len(data),
                "actual_bytes_read": len(data),
                "status": "OBSERVED",
                "data": data,
            })
            tx.snapshot_binding = f"snap_bind:4242:tx_{tx.transaction_id}"
            committed_tx = adapter.commit_capture_transaction(tx)
            self.assertEqual(committed_tx.metadata.get("identity_policy_id"), "strict-build-id")
            rcpt = adapter.issue_live_receipt_for_session(
                pid=4242,
                session_id="sess_custom_remote_1",
                snapshot_binding=committed_tx.snapshot_binding,
                transaction=committed_tx,
            )
            self.assertEqual(rcpt.target_constraints.get("identity_policy_id"), "strict-build-id")
            ok, reason = rcpt.verify(
                expected_session_id="sess_custom_remote_1",
                expected_pid=4242,
                expected_build_id="0123456789abcdef0123456789abcdef01234567",
                expected_snapshot_binding=committed_tx.snapshot_binding,
                identity_policy=adapter.get_identity_policy(),
            )
            self.assertTrue(ok, f"Receipt verification failed: {reason}")


if __name__ == "__main__":
    unittest.main()
