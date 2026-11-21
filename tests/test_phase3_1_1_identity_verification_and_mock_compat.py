"""Phase 3.1.1 — Target Identity Verification & Mock Compatibility Regression Tests.

Validates that:
1. Ordinary Python methods are supported.
2. Mock-based method replacement does not raise AttributeError: __code__.
3. MagicMock-based method replacement functions seamlessly.
4. Methods supporting force=True receive the parameter appropriately.
5. Subclasses/methods without a force parameter do not fail with TypeError.
6. Recent identity verification cache is respected when _allow_recent_sec > 0.
7. Forced identity refresh bypasses recent cache when _allow_recent_sec <= 0.
8. PID reuse during capture is detected and aborts with PIDReusedError.
9. Executable replacement during capture is detected and aborts with PIDReusedError.
"""

from __future__ import annotations

import os
import tempfile
import time
import unittest
from unittest.mock import MagicMock, Mock, patch
from typing import Any, Dict

from extractor.target_adapter import (
    CaptureTransaction,
    LocalTargetAdapter,
    PIDReusedError,
    RemoteSshTargetAdapter,
    TargetExecutionAdapter,
    _invoke_get_process_identity,
)


class CustomSubclassNoForce(LocalTargetAdapter):
    """Subclass implementing legacy get_process_identity with no force parameter."""

    def get_process_identity(self, pid: int) -> Dict[str, Any]:
        return {
            "pid": pid,
            "process_identity": f"{pid}:100000:boot-uuid-1",
            "start_time": "100000",
            "executable": "/bin/target_app",
            "executable_identity": "/bin/target_app:5001",
            "exe_inode": 5001,
            "boot_id": "boot-uuid-1",
            "build_id": "a" * 40,
        }


class CustomSubclassWithForce(LocalTargetAdapter):
    """Subclass implementing get_process_identity with force parameter and call tracking."""

    def __init__(self) -> None:
        super().__init__()
        self.call_history = []

    def get_process_identity(self, pid: int, force: bool = False) -> Dict[str, Any]:
        self.call_history.append((pid, force))
        return {
            "pid": pid,
            "process_identity": f"{pid}:100000:boot-uuid-1",
            "start_time": "100000",
            "executable": "/bin/target_app",
            "executable_identity": "/bin/target_app:5001",
            "exe_inode": 5001,
            "boot_id": "boot-uuid-1",
            "build_id": "a" * 40,
        }


class TestPhase311IdentityVerificationAndMockCompat(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory(prefix="test_p311_")
        os.chmod(self.tmpdir.name, 0o700)
        self.trust_store_path = os.path.join(self.tmpdir.name, "trust_store.json")
        self._orig_ts_path = os.environ.get("DYNAMICSTATE_TRUST_STORE_PATH")
        os.environ["DYNAMICSTATE_TRUST_STORE_PATH"] = self.trust_store_path
        from extractor.capture_backend import set_default_trust_store
        set_default_trust_store(None)

        self.pid = 4242
        self.session_id = "test-session-311"
        self.base_identity = {
            "pid": self.pid,
            "process_identity": f"{self.pid}:100000:boot-uuid-1",
            "start_time": "100000",
            "executable": "/bin/target_app",
            "executable_identity": "/bin/target_app:5001",
            "exe_inode": 5001,
            "boot_id": "boot-uuid-1",
            "build_id": "a" * 40,
        }

    def tearDown(self) -> None:
        from extractor.capture_backend import set_default_trust_store
        set_default_trust_store(None)
        if self._orig_ts_path is not None:
            os.environ["DYNAMICSTATE_TRUST_STORE_PATH"] = self._orig_ts_path
        else:
            os.environ.pop("DYNAMICSTATE_TRUST_STORE_PATH", None)
        try:
            self.tmpdir.cleanup()
        except Exception:
            pass

    # -------------------------------------------------------------------------
    # Scenario 1: Ordinary Python Method
    # -------------------------------------------------------------------------
    def test_01_ordinary_python_method(self) -> None:
        adapter = LocalTargetAdapter()
        with patch.object(adapter, "get_process_identity", return_value=dict(self.base_identity)):
            adapter.pin_target_identity(self.pid)
            ok, err = adapter.verify_pinned_identity(self.pid)
            self.assertTrue(ok)
            self.assertIsNone(err)

    # -------------------------------------------------------------------------
    # Scenario 2: Mock-Based Method Replacement
    # -------------------------------------------------------------------------
    def test_02_mock_based_method_replacement(self) -> None:
        adapter = LocalTargetAdapter()
        mock_fn = Mock(return_value=dict(self.base_identity))
        adapter.get_process_identity = mock_fn

        adapter.pin_target_identity(self.pid)
        # Should not raise AttributeError: __code__
        ok, err = adapter.verify_pinned_identity(self.pid)
        self.assertTrue(ok)
        self.assertIsNone(err)
        self.assertTrue(mock_fn.called)

    # -------------------------------------------------------------------------
    # Scenario 3: MagicMock-Based Method Replacement
    # -------------------------------------------------------------------------
    def test_03_magicmock_based_method_replacement(self) -> None:
        adapter = LocalTargetAdapter()
        with patch.object(adapter, "get_process_identity") as mock_fn:
            mock_fn.return_value = dict(self.base_identity)
            adapter.pin_target_identity(self.pid)
            # Must work with MagicMock seamlessly
            ok, err = adapter.verify_pinned_identity(self.pid)
            self.assertTrue(ok)
            self.assertIsNone(err)

    # -------------------------------------------------------------------------
    # Scenario 4: Method Supporting force=True
    # -------------------------------------------------------------------------
    def test_04_method_supporting_force_kwarg(self) -> None:
        adapter = CustomSubclassWithForce()
        adapter.pin_target_identity(self.pid)

        # When _allow_recent_sec <= 0.0, force must be True
        ok, err = adapter.verify_pinned_identity(self.pid, _allow_recent_sec=0.0)
        self.assertTrue(ok)
        self.assertEqual(adapter.call_history[-1], (self.pid, True))

        # When _allow_recent_sec > 0.0, force must be False
        ok, err = adapter.verify_pinned_identity(self.pid, _allow_recent_sec=2.0)
        self.assertTrue(ok)
        self.assertEqual(adapter.call_history[-1], (self.pid, False))

    # -------------------------------------------------------------------------
    # Scenario 5: Method Without Force Parameter
    # -------------------------------------------------------------------------
    def test_05_method_without_force_parameter(self) -> None:
        adapter = CustomSubclassNoForce()
        adapter.pin_target_identity(self.pid)

        # Should invoke safely without raising TypeError
        ok, err = adapter.verify_pinned_identity(self.pid, _allow_recent_sec=0.0)
        self.assertTrue(ok)
        self.assertIsNone(err)

    # -------------------------------------------------------------------------
    # Scenario 6: Recent Identity Verification Cache
    # -------------------------------------------------------------------------
    def test_06_recent_identity_verification_cache(self) -> None:
        adapter = RemoteSshTargetAdapter("localhost")
        adapter._ensure_tracking_state()
        adapter._pinned_identities[self.pid] = dict(self.base_identity)

        # Populate recent identity cache with timestamp = now
        adapter._last_identity_cache[self.pid] = (time.monotonic(), dict(self.base_identity))

        with patch.object(adapter, "get_process_identity") as mock_probe:
            # Verification allowing recent cache (< 2.0s) should not probe remote
            ok, err = adapter.verify_pinned_identity(self.pid, _allow_recent_sec=2.0)
            self.assertTrue(ok)
            mock_probe.assert_not_called()

    # -------------------------------------------------------------------------
    # Scenario 7: Forced Identity Refresh
    # -------------------------------------------------------------------------
    def test_07_forced_identity_refresh(self) -> None:
        adapter = RemoteSshTargetAdapter("localhost")
        adapter._ensure_tracking_state()
        adapter._pinned_identities[self.pid] = dict(self.base_identity)
        adapter._last_identity_cache[self.pid] = (time.monotonic(), dict(self.base_identity))

        with patch.object(adapter, "get_process_identity", return_value=dict(self.base_identity)) as mock_probe:
            # Forced refresh (_allow_recent_sec=0.0) must bypass recent cache
            ok, err = adapter.verify_pinned_identity(self.pid, _allow_recent_sec=0.0)
            self.assertTrue(ok)
            mock_probe.assert_called_once()

    # -------------------------------------------------------------------------
    # Scenario 8: PID Reuse During Capture
    # -------------------------------------------------------------------------
    def test_08_pid_reuse_during_capture(self) -> None:
        adapter = LocalTargetAdapter()
        with patch.object(adapter, "check_liveness", return_value=(True, None)), \
             patch.object(adapter, "get_process_identity") as mock_ident:
            mock_ident.return_value = dict(self.base_identity)
            tx = adapter.begin_capture_transaction(self.session_id, self.pid)
            adapter._record_physical_read(num_bytes=64, num_reads=1, data=b"D" * 64, pid=self.pid)

            # Target restarts with new start_time
            reused_ident = dict(self.base_identity)
            reused_ident["start_time"] = "999999"
            reused_ident["process_identity"] = f"{self.pid}:999999:boot-uuid-1"
            mock_ident.return_value = reused_ident

            with self.assertRaises(PIDReusedError):
                adapter.commit_capture_transaction(tx)
            self.assertTrue(tx.aborted)

    # -------------------------------------------------------------------------
    # Scenario 9: Executable Replacement During Capture
    # -------------------------------------------------------------------------
    def test_09_executable_replacement_during_capture(self) -> None:
        adapter = LocalTargetAdapter()
        with patch.object(adapter, "check_liveness", return_value=(True, None)), \
             patch.object(adapter, "get_process_identity") as mock_ident:
            mock_ident.return_value = dict(self.base_identity)
            tx = adapter.begin_capture_transaction(self.session_id, self.pid)
            adapter._record_physical_read(num_bytes=64, num_reads=1, data=b"D" * 64, pid=self.pid)

            # Target binary replaced during transaction (inode changed)
            replaced_ident = dict(self.base_identity)
            replaced_ident["exe_inode"] = 9999
            replaced_ident["executable_identity"] = "/bin/target_app:9999"
            mock_ident.return_value = replaced_ident

            with self.assertRaises(PIDReusedError):
                adapter.commit_capture_transaction(tx)
            self.assertTrue(tx.aborted)


if __name__ == "__main__":
    unittest.main()
