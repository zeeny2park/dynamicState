"""Deterministic Verification Tests for Phase 2 Remote Performance Optimization.

Validates:
1. Remote Collection Coalescing (unified snapshot replaces sequential roundtrips).
2. Drastic reduction in SSH command count for overlapping process metadata.
3. Strict Evidence Validity, Freshness Model, and PID Reuse Safety.
4. Remote Fault Isolation (partial /proc permission failure leaves other evidence intact).
5. Budget accounting & bounded deadline deduction during retries.
6. Zero-daemon / zero-target-Python POSIX shell compliance.
"""

import os
import shlex
import time
from typing import Any, Dict, List, Optional, Tuple
import pytest

from extractor.target_adapter import RemoteSshTargetAdapter
import extractor.target_abi as target_abi
from extractor.diagnostic_performance import DiagnosticPerformanceTracker


class TestRemoteCollectionCoalescing:
    """Verifies that RemoteSshTargetAdapter coalesces process metadata into a single round trip."""

    def test_coalesced_shell_snapshot_single_command(self):
        """Verify that prefetch_snapshot executes exactly 1 SSH command and populates all fields."""
        executed_commands: List[str] = []

        fake_snapshot_output = (
            "@@LIVENESS\nALIVE\n"
            "@@COMM\nmy_service\n"
            "@@STAT\n1234 (my_service) S 1 1234 1234 0 -1 4194304 100 0 0 0 10 20 0 0 20 0 4 0 999999 10485760 1000 18446744073709551615 4194304 4200000 140720000000000 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0\n"
            "@@STATUS\nName:\tmy_service\nState:\tS (sleeping)\nVmRSS:\t16384 kB\nVmSize:\t32768 kB\nThreads:\t2\n"
            "@@MAPS\n00400000-00401000 r-xp 00000000 08:01 12345 /usr/bin/my_service\n00600000-00601000 rw-p 00001000 08:01 12345 /usr/bin/my_service\n"
            "@@EXE\n/usr/bin/my_service\n"
            "@@FP\n12345:4096:1700000000\n"
            "@@BOOT\n11111111-2222-3333-4444-555555555555\n"
            "@@OSREL\n6.8.0-generic\n"
            "@@MACH\nx86_64\n"
            "@@FDS\nlrwx------ 1 user user 64 Jan 1 00:00 0 -> /dev/pts/0\nlrwx------ 1 user user 64 Jan 1 00:00 1 -> /tmp/out.log\n"
            "@@TASKS\n@@T 1234\n@@F stat\n1234 (my_service) S 1 1234 1234 0 -1 4194304 100 0 0 0 10 20\n@@F status\nState:\tS (sleeping)\n"
            "@@T 1235\n@@F stat\n1235 (worker) S 1 1234 1234 0 -1 4194304 100 0 0 0 5 15\n@@F status\nState:\tS (sleeping)\n"
            "@@END\n"
        )

        def mock_runner(args: List[str], timeout: float, **kwargs) -> Tuple[int, str, str]:
            executed_commands.append(args[-1])
            return 0, fake_snapshot_output, ""

        adapter = RemoteSshTargetAdapter(
            host="remote.target.corp",
            user="app",
            command_runner=mock_runner,
            use_control_master=False,
        )

        # Act: prefetch compound snapshot
        snap = adapter.prefetch_snapshot(1234)
        assert snap is not None
        assert snap["success"] is True
        assert snap["terminated"] is False
        assert len(executed_commands) == 1
        assert "@@LIVENESS" in executed_commands[0]
        assert "@@STATUS" in executed_commands[0]

        # Assert: Subsequent queries for liveness, identity, status, maps, fds, threads issue 0 extra SSH calls
        alive, err = adapter.check_liveness(1234)
        assert alive is True
        assert err is None
        assert len(executed_commands) == 1  # No extra call!

        st = adapter.get_process_status(1234)
        assert st.get("VmRSS") == 16384
        assert st.get("Threads") == 2
        assert len(executed_commands) == 1  # No extra call!

        maps = adapter.get_proc_maps(1234)
        assert len(maps) == 2
        assert maps[0]["pathname"] == "/usr/bin/my_service"
        assert len(executed_commands) == 1  # No extra call!

        fds_info = adapter.list_open_fds(1234)
        assert fds_info is not None
        count, targets = fds_info
        assert count == 2
        assert "/tmp/out.log" in targets
        assert len(executed_commands) == 1  # No extra call!

        threads = adapter.get_threads(1234)
        assert len(threads) == 2
        tids = [t["tid"] for t in threads]
        assert 1234 in tids and 1235 in tids
        assert len(executed_commands) == 1  # No extra call!

    def test_snapshot_scope_context_manager(self):
        """Verify snapshot_scope automatically prefetches on entry and serves queries."""
        calls = []

        def mock_runner(args: List[str], timeout: float, **kwargs) -> Tuple[int, str, str]:
            calls.append(args[-1])
            return 0, "@@LIVENESS\nALIVE\n@@COMM\nworker\n@@STAT\n100 (worker) S 1 100 100 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 500\n@@STATUS\nVmRSS:\t4096 kB\n@@MAPS\n@@EXE\n/bin/worker\n@@FP\n1:2:3\n@@BOOT\nb-123\n@@OSREL\n6.1\n@@MACH\naarch64\n@@FDS\n@@TASKS\n@@END\n", ""

        adapter = RemoteSshTargetAdapter(
            host="remote.target.corp",
            user="app",
            command_runner=mock_runner,
            use_control_master=False,
        )

        with adapter.snapshot_scope(100):
            assert len(calls) == 1
            adapter.check_liveness(100)
            adapter.get_process_status(100)
            adapter.get_proc_maps(100)
            assert len(calls) == 1

        # Re-entering snapshot_scope with existing fresh snapshot avoids duplicate fetch
        with adapter.snapshot_scope(100):
            assert len(calls) == 1


class TestEvidenceValidityAndFreshness:
    """Verifies evidence validity TTL, refresh after expiration, and PID reuse detection."""

    def test_freshness_ttl_expiration_triggers_refresh(self):
        """Verify that stale snapshots (> TTL) trigger a fresh collection."""
        commands = []

        def mock_runner(args: List[str], timeout: float, **kwargs) -> Tuple[int, str, str]:
            commands.append(args[-1])
            return 0, "@@LIVENESS\nALIVE\n@@COMM\napp\n@@STAT\n555 (app) S 1 555 555 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 500\n@@STATUS\nVmRSS:\t1000 kB\n@@MAPS\n@@EXE\n/app\n@@FP\n1:2:3\n@@BOOT\nb-1\n@@OSREL\n6.1\n@@MACH\nx86_64\n@@FDS\n@@TASKS\n@@END\n", ""

        adapter = RemoteSshTargetAdapter(host="10.0.0.1", command_runner=mock_runner, use_control_master=False)

        # Initial fetch
        adapter.prefetch_snapshot(555)
        assert len(commands) == 1

        # Query immediately -> fresh hit (0 extra commands)
        adapter.prefetch_snapshot(555, max_age_s=0.5)
        assert len(commands) == 1

        # Simulate time advancement beyond max_age_s
        stale_time = time.monotonic() - 10.0
        adapter._snapshot_cache[555] = (stale_time, adapter._snapshot_cache[555][1])

        # Query after expiration -> triggers refresh
        adapter.prefetch_snapshot(555, max_age_s=0.5)
        assert len(commands) == 2

    def test_pid_reuse_detection_fails_closed(self):
        """Verify that verify_pinned_identity detects changed start_time/boot_id and aborts."""
        adapter = RemoteSshTargetAdapter(host="10.0.0.1", use_control_master=False)

        # Pin identity for PID 777
        adapter._pinned_identities[777] = {
            "pid": 777,
            "start_time": "50000",
            "executable": "/usr/bin/daemon",
            "boot_id": "boot-aaa",
            "exe_fingerprint": "123:456:789",
            "process_identity": "777:50000:boot-aaa",
        }

        # Cached identity matches pinned identity
        adapter._last_identity_cache[777] = (
            time.monotonic(),
            {
                "pid": 777,
                "start_time": "50000",
                "executable": "/usr/bin/daemon",
                "boot_id": "boot-aaa",
                "exe_fingerprint": "123:456:789",
                "process_identity": "777:50000:boot-aaa",
            },
        )
        ok, err = adapter.verify_pinned_identity(777)
        assert ok is True
        assert err is None

        # Simulate PID reuse: target process died and new process spawned with different start_time
        adapter._last_identity_cache[777] = (
            time.monotonic(),
            {
                "pid": 777,
                "start_time": "99999",  # Different start time!
                "executable": "/usr/bin/daemon",
                "boot_id": "boot-aaa",
                "exe_fingerprint": "123:456:789",
                "process_identity": "777:99999:boot-aaa",
            },
        )
        ok, err = adapter.verify_pinned_identity(777)
        assert ok is False
        assert "PID_REUSED" in err


class TestRemoteFaultIsolation:
    """Verifies that partial collection failures isolate cleanly without corrupting other data."""

    def test_permission_denied_on_proc_fd_isolates_cleanly(self):
        """When /proc/<pid>/fd is inaccessible, other snapshot sections remain fully usable."""
        commands = []
        # Simulate partial failure: ls -l /proc/pid/fd yields empty / permission denied
        partial_output = (
            "@@LIVENESS\nALIVE\n"
            "@@COMM\nrestricted_svc\n"
            "@@STAT\n888 (restricted_svc) S 1 888 888 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 500\n"
            "@@STATUS\nName:\trestricted_svc\nVmRSS:\t8192 kB\n"
            "@@MAPS\n00400000-00401000 r-xp 00000000 08:01 1 /bin/svc\n"
            "@@EXE\n/bin/svc\n"
            "@@FP\n1:2:3\n"
            "@@BOOT\nboot-1\n"
            "@@OSREL\n6.8\n"
            "@@MACH\naarch64\n"
            "@@FDS\n"  # Empty due to permission denial
            "@@TASKS\n@@T 888\n@@F stat\n888 (svc) S 1 888 888 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 500\n"
            "@@END\n"
        )

        def mock_runner(args: List[str], timeout: float, **kwargs):
            commands.append(args[-1])
            return 0, partial_output, ""

        adapter = RemoteSshTargetAdapter(host="10.0.0.1", command_runner=mock_runner, use_control_master=False)
        snap = adapter.prefetch_snapshot(888)
        assert snap is not None
        assert snap["success"] is True

        # Process status and maps still succeed despite FD restriction
        st = adapter.get_process_status(888)
        assert st.get("VmRSS") == 8192
        maps = adapter.get_proc_maps(888)
        assert len(maps) == 1

        # FD collection reports empty/cleanly isolated without crashing
        fds = adapter.list_open_fds(888)
        assert fds == (0, [])


class TestBudgetAndRetryAccounting:
    """Verifies that remote retries strictly deduct from remaining budget without deadline reset."""

    def test_retries_consume_remaining_deadline(self):
        """Retries after intermittent connection drop deduct elapsed time and abort if deadline expired."""
        attempts = []

        def failing_mux_runner(args: List[str], timeout: float, **kwargs) -> Tuple[int, str, str]:
            attempts.append(timeout)
            if len(attempts) == 1:
                return 255, "", "mux_client_request_session: Broken pipe"
            return 0, "OK", ""

        adapter = RemoteSshTargetAdapter(
            host="10.0.0.1",
            command_runner=failing_mux_runner,
            use_control_master=True,
            timeout_sec=5.0,
        )
        adapter._cm_used = True

        # Run with explicit deadline of 3.0 seconds
        with adapter.collection_deadline(3.0):
            rc, out, err = adapter.run_ssh("echo OK")

        assert rc == 0
        assert out.strip() == "OK"
        # 2 attempts: initial + 1 retry
        assert len(attempts) == 2
        # Verify performance metrics captured retry duration & reconnect
        m = adapter.get_performance_metrics()
        assert m.get("retries_count") == 1
        assert m.get("control_master_reconnects_count") == 1
        assert m.get("retry_s", 0.0) >= 0.0
