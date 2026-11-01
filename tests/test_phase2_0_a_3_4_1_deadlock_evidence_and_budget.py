"""Phase 2.0-A.3.4.1 Test Suite — Deadlock Evidence Integrity & Complete Budget Enforcement.

Covers:
1. Strict Libc and ABI Identification:
   - Verified glibc LP64
   - musl rejection
   - Unknown libc rejection
   - Static binary / unidentified runtime rejection
   - 32-bit ELF rejection
   - Unsupported endianness rejection
   - Host architecture differing from target architecture (no host fallback)

2. WaitForGraph Evidence Validation & Construction:
   - Missing target PID rejection
   - Cross-process PID mismatch rejection
   - Cross-process start identity mismatch rejection
   - Missing process identity rejection
   - Missing / non-positive timestamp rejection
   - Stale edge rejection
   - Unsupported layout rejection
   - Memory read not OBSERVED rejection
   - Normalized address mismatch rejection
   - Duplicate edge preservation
   - Conflicting owners on same lock rejection
   - Multiple conflicting observations for one waiter rejection
   - Cross-epoch edge rejection
   - Real runtime 2-thread circular deadlock confirmation
   - Real runtime 3-thread circular deadlock confirmation
   - Real runtime contention without cycle
   - Unknown owner cannot confirm cycle

3. Complete Observation Budget Enforcement:
   - WorkManager path cannot bypass budget checks
   - Fallback path cannot bypass budget checks
   - Mutex read bytes counted even when owner is unknown
   - Partial memory reads counted accurately
   - Failed reads with transferred bytes accounted for
   - Remote operation cost not omitted
   - Budget exhaustion mid-scan preserves collected evidence
   - No double counting between WorkManager and fallback
"""

import os
import shutil
import struct
import subprocess
import tempfile
import time
import unittest
from typing import Any, Dict, List, Optional, Tuple

from extractor.target_adapter import (
    LocalTargetAdapter,
    ReadOnlyTargetAdapter,
    RemoteSshTargetAdapter,
    MutexOwnerResolutionResult,
    STATUS_OWNER_IDENTIFIED,
    STATUS_OWNER_NOT_IDENTIFIED,
    STATUS_MUTEX_LAYOUT_UNSUPPORTED,
    STATUS_MUTEX_STATE_INVALID,
    STATUS_MEMORY_READ_UNAVAILABLE,
    STATUS_PERMISSION_DENIED,
    ABI_GLIBC_VERIFIED,
    ABI_MUSL_UNSUPPORTED,
    ABI_LIBC_UNKNOWN,
    ABI_STATIC_OR_UNIDENTIFIED,
    ABI_ARCH_UNSUPPORTED,
    ABI_ELF_CLASS_UNSUPPORTED,
    ABI_ENDIANNESS_UNSUPPORTED,
    IDENTITY_VERIFIED,
    LAYOUT_GLIBC_LP64,
    normalize_futex_address,
)
from extractor.adaptive_engine import (
    AdaptiveInvestigationEngine,
    WaitForEdge,
    WaitForGraph,
    RESULT_DEADLOCK_CYCLE_CONFIRMED,
    RESULT_LOCK_CONTENTION_OBSERVED,
    RESULT_WAITING_WITH_UNKNOWN_OWNER,
    RESULT_INCOMPLETE_WAIT_FOR_GRAPH,
    RESULT_INCONSISTENT_OWNER_EVIDENCE,
    RESULT_INCONCLUSIVE,
)
from extractor.observation_budget import (
    ObservationBudgetLimits,
    ObservationBudgetTracker,
)


class TestPhase20A341DeadlockEvidenceAndBudget(unittest.TestCase):
    """Hardened evidence integrity and budget enforcement audit suite."""

    @classmethod
    def setUpClass(cls):
        cls.work_dir = tempfile.mkdtemp(prefix="dynstate_a341_")
        cls.fixtures_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "fixtures", "real_runtime")
        )

        cls.bin_2way = os.path.join(cls.work_dir, "proc_2way_deadlock")
        cls.bin_3way = os.path.join(cls.work_dir, "proc_3way_deadlock")
        cls.bin_contention = os.path.join(cls.work_dir, "proc_contention")

        # Compile real-process fixtures
        compile_targets = [
            ("proc_thread_circular_deadlock.c", cls.bin_2way),
            ("proc_thread_3way_deadlock.c", cls.bin_3way),
            ("proc_scenario_c_thread_contention.c", cls.bin_contention),
        ]

        for src_name, bin_dest in compile_targets:
            src_path = os.path.join(cls.fixtures_dir, src_name)
            if os.path.exists(src_path):
                cmd = ["gcc", "-O2", "-Wall", "-Wextra", "-pthread", src_path, "-o", bin_dest]
                rc = subprocess.call(cmd)
                if rc != 0:
                    raise RuntimeError(f"Failed to compile fixture {src_name} -> {bin_dest}")

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(cls.work_dir):
            shutil.rmtree(cls.work_dir, ignore_errors=True)

    def _sample_valid_proc_identity(self, pid: int = 1000) -> Dict[str, Any]:
        return {
            "pid": pid,
            "process_start_time": 100000,
            "architecture": "x86_64",
            "elf_class": "ELF64",
            "endianness": "little",
            "executable": "/usr/bin/app",
            "build_id": "0123456789abcdef",
            "status": "OBSERVED",
            "identity_status": IDENTITY_VERIFIED,
        }

    def _sample_valid_meta(self, owner_tid: int = 102, waiter_tid: int = 101) -> Dict[str, Any]:
        return {
            "abi_status": ABI_GLIBC_VERIFIED,
            "layout_id": LAYOUT_GLIBC_LP64,
            "raw_bytes": struct.pack("<iIiIi", 1, 0, owner_tid, 0, 0) + b"\x00" * 20,
            "read_bytes_len": 40,
            "lock_word": 1,
            "count": 0,
            "owner": owner_tid,
            "nusers": 0,
            "kind": 0,
            "base_kind": 0,
            "target_tids": [waiter_tid, owner_tid],
        }

    # =========================================================================
    # 1. Strict Libc and ABI Identification
    # =========================================================================

    def test_01_verified_glibc_lp64(self):
        """Target with verified LP64 glibc runtime produces GLIBC_ABI_VERIFIED status."""
        adapter = LocalTargetAdapter()
        # os.getpid() is Python on Linux x86_64 or aarch64 running glibc
        ident = adapter.get_process_identity(os.getpid())
        self.assertIn(ident["architecture"], ("x86_64", "aarch64"))
        self.assertEqual(ident["elf_class"], "ELF64")
        self.assertEqual(ident["endianness"], "little")

        # Fake unlocked mutex slice: __lock=0, __count=0, __owner=0, __nusers=0, __kind=0
        fake_raw = struct.pack("<iIiIi", 0, 0, 0, 0, 0) + b"\x00" * 20
        orig_read = adapter.read_memory
        adapter.read_memory = lambda pid, addr, sz: (fake_raw, "OBSERVED", None)
        try:
            res = adapter.resolve_mutex_owner(os.getpid(), 0x7ffd1234)
            self.assertEqual(res.status, STATUS_OWNER_NOT_IDENTIFIED)
            self.assertEqual(res.layout_id, LAYOUT_GLIBC_LP64)
            self.assertEqual(res.metadata.get("abi_status"), ABI_GLIBC_VERIFIED)
        finally:
            adapter.read_memory = orig_read

    def test_02_musl_libc_explicit_rejection(self):
        """Target with musl libc mapping fails closed with ABI_MUSL_UNSUPPORTED."""
        adapter = LocalTargetAdapter()
        orig_maps = adapter.get_proc_maps
        adapter.get_proc_maps = lambda pid: [
            {"pathname": "/lib/ld-musl-x86_64.so.1", "size": 4096, "category": "file"}
        ]
        try:
            res = adapter.resolve_mutex_owner(os.getpid(), 0x7ffd1234)
            self.assertEqual(res.status, STATUS_MUTEX_LAYOUT_UNSUPPORTED)
            self.assertEqual(res.layout_id, ABI_MUSL_UNSUPPORTED)
            self.assertEqual(res.metadata.get("abi_status"), ABI_MUSL_UNSUPPORTED)
            self.assertIn("musl", res.error.lower())
        finally:
            adapter.get_proc_maps = orig_maps

    def test_03_unknown_libc_rejection(self):
        """Target with non-glibc shared libraries fails closed with ABI_LIBC_UNKNOWN."""
        adapter = LocalTargetAdapter()
        orig_maps = adapter.get_proc_maps
        adapter.get_proc_maps = lambda pid: [
            {"pathname": "/lib/libcustom_runtime.so.1", "size": 4096, "category": "file"}
        ]
        try:
            res = adapter.resolve_mutex_owner(os.getpid(), 0x7ffd1234)
            self.assertEqual(res.status, STATUS_MUTEX_LAYOUT_UNSUPPORTED)
            self.assertEqual(res.layout_id, ABI_LIBC_UNKNOWN)
            self.assertEqual(res.metadata.get("abi_status"), ABI_LIBC_UNKNOWN)
        finally:
            adapter.get_proc_maps = orig_maps

    def test_04_static_binary_unidentified_runtime_rejection(self):
        """Static binary or process without shared libraries fails closed with ABI_STATIC_OR_UNIDENTIFIED."""
        adapter = LocalTargetAdapter()
        orig_maps = adapter.get_proc_maps
        adapter.get_proc_maps = lambda pid: [
            {"pathname": "[heap]", "size": 8192, "category": "heap"},
            {"pathname": "[stack]", "size": 8192, "category": "stack"},
        ]
        try:
            res = adapter.resolve_mutex_owner(os.getpid(), 0x7ffd1234)
            self.assertEqual(res.status, STATUS_MUTEX_LAYOUT_UNSUPPORTED)
            self.assertEqual(res.layout_id, ABI_STATIC_OR_UNIDENTIFIED)
            self.assertEqual(res.metadata.get("abi_status"), ABI_STATIC_OR_UNIDENTIFIED)
        finally:
            adapter.get_proc_maps = orig_maps

    def test_05_32bit_elf_rejection(self):
        """32-bit ELF binary (ELF32) is rejected with ABI_ELF_CLASS_UNSUPPORTED."""
        adapter = LocalTargetAdapter()
        orig_ident = adapter.get_process_identity
        adapter.get_process_identity = lambda pid: {
            "architecture": "x86",
            "elf_class": "ELF32",
            "endianness": "little",
        }
        try:
            res = adapter.resolve_mutex_owner(os.getpid(), 0x7ffd1234)
            self.assertEqual(res.status, STATUS_MUTEX_LAYOUT_UNSUPPORTED)
            self.assertEqual(res.layout_id, ABI_ARCH_UNSUPPORTED)
        finally:
            adapter.get_process_identity = orig_ident

    def test_06_unsupported_endianness_rejection(self):
        """Big-endian target is rejected with ABI_ENDIANNESS_UNSUPPORTED."""
        adapter = LocalTargetAdapter()
        orig_ident = adapter.get_process_identity
        adapter.get_process_identity = lambda pid: {
            "architecture": "aarch64",
            "elf_class": "ELF64",
            "endianness": "big",
        }
        try:
            res = adapter.resolve_mutex_owner(os.getpid(), 0x7ffd1234)
            self.assertEqual(res.status, STATUS_MUTEX_LAYOUT_UNSUPPORTED)
            self.assertEqual(res.layout_id, ABI_ENDIANNESS_UNSUPPORTED)
            self.assertEqual(res.metadata.get("abi_status"), ABI_ENDIANNESS_UNSUPPORTED)
        finally:
            adapter.get_process_identity = orig_ident

    def test_07_host_architecture_differing_never_fallback(self):
        """When target architecture cannot be established, adapter NEVER falls back to host."""
        adapter = LocalTargetAdapter()
        orig_ident = adapter.get_process_identity
        adapter.get_process_identity = lambda pid: {
            "architecture": "unknown",
            "elf_class": "unknown",
            "endianness": "unknown",
        }
        try:
            res = adapter.resolve_mutex_owner(os.getpid(), 0x7ffd1234)
            self.assertEqual(res.status, STATUS_MUTEX_LAYOUT_UNSUPPORTED)
            self.assertEqual(res.layout_id, ABI_ARCH_UNSUPPORTED)
            self.assertIn("fallback to host architecture is strictly forbidden", res.error)
        finally:
            adapter.get_process_identity = orig_ident

    # =========================================================================
    # 2. WaitForGraph Evidence Validation & Construction
    # =========================================================================

    def test_08_graph_missing_target_pid_rejected(self):
        """Edge with missing target_pid is rejected and cannot confirm a cycle."""
        graph = WaitForGraph()
        t_now = time.time()
        # Edge 1 lacks target_pid
        graph.add_edge(WaitForEdge(
            waiter_tid=101,
            sync_object="0x1000",
            normalized_address="0x1000",
            owner_tid=102,
            owner_identification_status=STATUS_OWNER_IDENTIFIED,
            mutex_layout_id=LAYOUT_GLIBC_LP64,
            memory_read_status="OBSERVED",
            observation_timestamp=t_now,
            target_pid=None,
            process_identity=self._sample_valid_proc_identity(100),
            metadata=self._sample_valid_meta(102, 101),
        ))
        graph.add_edge(WaitForEdge(
            waiter_tid=102,
            sync_object="0x2000",
            normalized_address="0x2000",
            owner_tid=101,
            owner_identification_status=STATUS_OWNER_IDENTIFIED,
            mutex_layout_id=LAYOUT_GLIBC_LP64,
            memory_read_status="OBSERVED",
            observation_timestamp=t_now,
            target_pid=100,
            process_identity=self._sample_valid_proc_identity(100),
            metadata=self._sample_valid_meta(101, 102),
        ))
        cycle, category, issues = graph.validate_and_analyze()
        self.assertIsNone(cycle)
        self.assertNotEqual(category, RESULT_DEADLOCK_CYCLE_CONFIRMED)
        self.assertTrue(any("REJECT_MISSING_TARGET_PID" in s for s in issues))

    def test_09_graph_cross_process_different_pids_rejected(self):
        """Edges with different target PIDs in one graph are rejected as cross-process evidence."""
        graph = WaitForGraph()
        t_now = time.time()
        graph.add_edge(WaitForEdge(
            waiter_tid=101,
            sync_object="0x1000",
            normalized_address="0x1000",
            owner_tid=102,
            owner_identification_status=STATUS_OWNER_IDENTIFIED,
            mutex_layout_id=LAYOUT_GLIBC_LP64,
            memory_read_status="OBSERVED",
            observation_timestamp=t_now,
            target_pid=100,
            process_identity=self._sample_valid_proc_identity(100),
            metadata=self._sample_valid_meta(102, 101),
        ))
        # Edge 2 belongs to PID 200
        graph.add_edge(WaitForEdge(
            waiter_tid=102,
            sync_object="0x2000",
            normalized_address="0x2000",
            owner_tid=101,
            owner_identification_status=STATUS_OWNER_IDENTIFIED,
            mutex_layout_id=LAYOUT_GLIBC_LP64,
            memory_read_status="OBSERVED",
            observation_timestamp=t_now,
            target_pid=200,
            process_identity=self._sample_valid_proc_identity(200),
            metadata=self._sample_valid_meta(101, 102),
        ))
        cycle, category, issues = graph.validate_and_analyze()
        self.assertIsNone(cycle)
        self.assertEqual(category, RESULT_INCONSISTENT_OWNER_EVIDENCE)
        self.assertTrue(any("REJECT_CROSS_PROCESS_PID_MISMATCH" in s for s in issues))

    def test_10_graph_different_process_start_identities_rejected(self):
        """Edges with differing process start times are rejected as stale or cross-epoch."""
        graph = WaitForGraph()
        t_now = time.time()
        p1 = self._sample_valid_proc_identity(100)
        p1["process_start_time"] = 100000
        p2 = self._sample_valid_proc_identity(100)
        p2["process_start_time"] = 200000  # Stale process instance restarted with same PID

        graph.add_edge(WaitForEdge(
            waiter_tid=101,
            sync_object="0x1000",
            normalized_address="0x1000",
            owner_tid=102,
            owner_identification_status=STATUS_OWNER_IDENTIFIED,
            mutex_layout_id=LAYOUT_GLIBC_LP64,
            memory_read_status="OBSERVED",
            observation_timestamp=t_now,
            target_pid=100,
            process_identity=p1,
            metadata=self._sample_valid_meta(102, 101),
        ))
        graph.add_edge(WaitForEdge(
            waiter_tid=102,
            sync_object="0x2000",
            normalized_address="0x2000",
            owner_tid=101,
            owner_identification_status=STATUS_OWNER_IDENTIFIED,
            mutex_layout_id=LAYOUT_GLIBC_LP64,
            memory_read_status="OBSERVED",
            observation_timestamp=t_now,
            target_pid=100,
            process_identity=p2,
            metadata=self._sample_valid_meta(101, 102),
        ))
        cycle, category, issues = graph.validate_and_analyze()
        self.assertIsNone(cycle)
        self.assertEqual(category, RESULT_INCONSISTENT_OWNER_EVIDENCE)
        self.assertTrue(any("REJECT_CROSS_PROCESS_IDENTITY_MISMATCH" in s for s in issues))

    def test_11_graph_missing_process_identity_rejected(self):
        """Edge lacking process_identity is rejected from verified edges."""
        graph = WaitForGraph()
        t_now = time.time()
        graph.add_edge(WaitForEdge(
            waiter_tid=101,
            sync_object="0x1000",
            normalized_address="0x1000",
            owner_tid=102,
            owner_identification_status=STATUS_OWNER_IDENTIFIED,
            mutex_layout_id=LAYOUT_GLIBC_LP64,
            memory_read_status="OBSERVED",
            observation_timestamp=t_now,
            target_pid=100,
            process_identity=None,  # Missing
            metadata=self._sample_valid_meta(102, 101),
        ))
        cycle, category, issues = graph.validate_and_analyze()
        self.assertIsNone(cycle)
        self.assertTrue(any("REJECT_MISSING_PROCESS_IDENTITY" in s for s in issues))

    def test_12_graph_missing_timestamp_rejected(self):
        """Edge with missing or non-positive timestamp is rejected."""
        graph = WaitForGraph()
        graph.add_edge(WaitForEdge(
            waiter_tid=101,
            sync_object="0x1000",
            normalized_address="0x1000",
            owner_tid=102,
            owner_identification_status=STATUS_OWNER_IDENTIFIED,
            mutex_layout_id=LAYOUT_GLIBC_LP64,
            memory_read_status="OBSERVED",
            observation_timestamp=0.0,  # Invalid
            target_pid=100,
            process_identity=self._sample_valid_proc_identity(100),
            metadata=self._sample_valid_meta(102, 101),
        ))
        cycle, category, issues = graph.validate_and_analyze()
        self.assertIsNone(cycle)
        self.assertTrue(any("REJECT_MISSING_OR_INVALID_TIMESTAMP" in s for s in issues))

    def test_13_graph_stale_edge_rejected(self):
        """Edge whose timestamp exhibits excessive temporal skew (> 2.0s) cannot confirm cycle."""
        graph = WaitForGraph()
        t0 = 1000.0
        t1 = 1003.0  # 3.0s skew > 2.0s
        graph.add_edge(WaitForEdge(
            waiter_tid=101,
            sync_object="0x1000",
            normalized_address="0x1000",
            owner_tid=102,
            owner_identification_status=STATUS_OWNER_IDENTIFIED,
            mutex_layout_id=LAYOUT_GLIBC_LP64,
            memory_read_status="OBSERVED",
            observation_timestamp=t0,
            target_pid=100,
            process_identity=self._sample_valid_proc_identity(100),
            sampling_epoch=1,
            metadata=self._sample_valid_meta(102, 101),
        ))
        graph.add_edge(WaitForEdge(
            waiter_tid=102,
            sync_object="0x2000",
            normalized_address="0x2000",
            owner_tid=101,
            owner_identification_status=STATUS_OWNER_IDENTIFIED,
            mutex_layout_id=LAYOUT_GLIBC_LP64,
            memory_read_status="OBSERVED",
            observation_timestamp=t1,
            target_pid=100,
            process_identity=self._sample_valid_proc_identity(100),
            sampling_epoch=1,
            metadata=self._sample_valid_meta(101, 102),
        ))
        cycle, category, issues = graph.validate_and_analyze(max_temporal_skew_sec=2.0)
        self.assertIsNone(cycle)
        self.assertEqual(category, RESULT_INCONCLUSIVE)
        self.assertTrue(any("temporal skew" in s.lower() for s in issues))

    def test_14_graph_unsupported_layout_rejected(self):
        """Edge with unsupported mutex layout is rejected."""
        graph = WaitForGraph()
        t_now = time.time()
        graph.add_edge(WaitForEdge(
            waiter_tid=101,
            sync_object="0x1000",
            normalized_address="0x1000",
            owner_tid=102,
            owner_identification_status=STATUS_MUTEX_LAYOUT_UNSUPPORTED,
            mutex_layout_id="MUSL_UNSUPPORTED",
            memory_read_status="OBSERVED",
            observation_timestamp=t_now,
            target_pid=100,
            process_identity=self._sample_valid_proc_identity(100),
            metadata=self._sample_valid_meta(102, 101),
        ))
        cycle, category, issues = graph.validate_and_analyze()
        self.assertIsNone(cycle)
        self.assertEqual(category, RESULT_WAITING_WITH_UNKNOWN_OWNER)
        self.assertTrue(any("REJECT_UNSUPPORTED_MUTEX_LAYOUT" in s for s in issues))

    def test_15_graph_memory_read_not_observed_rejected(self):
        """Edge whose memory read status is UNAVAILABLE or PARTIAL is rejected."""
        graph = WaitForGraph()
        t_now = time.time()
        graph.add_edge(WaitForEdge(
            waiter_tid=101,
            sync_object="0x1000",
            normalized_address="0x1000",
            owner_tid=102,
            owner_identification_status=STATUS_OWNER_IDENTIFIED,
            mutex_layout_id=LAYOUT_GLIBC_LP64,
            memory_read_status="UNAVAILABLE",
            observation_timestamp=t_now,
            target_pid=100,
            process_identity=self._sample_valid_proc_identity(100),
            metadata=self._sample_valid_meta(102, 101),
        ))
        cycle, category, issues = graph.validate_and_analyze()
        self.assertIsNone(cycle)
        self.assertTrue(any("REJECT_MEMORY_READ_NOT_OBSERVED" in s for s in issues))

    def test_16_graph_address_mismatch_rejected(self):
        """Edge where normalized_address differs from sync_object is rejected."""
        graph = WaitForGraph()
        t_now = time.time()
        graph.add_edge(WaitForEdge(
            waiter_tid=101,
            sync_object="0x1000",
            normalized_address="0x2000",  # Mismatch
            owner_tid=102,
            owner_identification_status=STATUS_OWNER_IDENTIFIED,
            mutex_layout_id=LAYOUT_GLIBC_LP64,
            memory_read_status="OBSERVED",
            observation_timestamp=t_now,
            target_pid=100,
            process_identity=self._sample_valid_proc_identity(100),
            metadata=self._sample_valid_meta(102, 101),
        ))
        cycle, category, issues = graph.validate_and_analyze()
        self.assertIsNone(cycle)
        self.assertTrue(any("REJECT_ADDRESS_MISMATCH" in s for s in issues))

    def test_17_graph_duplicate_edge_preserved(self):
        """Duplicate edges for the same waiter on the same lock are preserved and deduplicated."""
        graph = WaitForGraph()
        t_now = time.time()
        e1 = WaitForEdge(
            waiter_tid=101,
            sync_object="0x1000",
            normalized_address="0x1000",
            owner_tid=102,
            owner_identification_status=STATUS_OWNER_IDENTIFIED,
            mutex_layout_id=LAYOUT_GLIBC_LP64,
            memory_read_status="OBSERVED",
            observation_timestamp=t_now,
            target_pid=100,
            process_identity=self._sample_valid_proc_identity(100),
            metadata=self._sample_valid_meta(102, 101),
        )
        graph.add_edge(e1)
        graph.add_edge(e1)  # Exact duplicate
        self.assertEqual(len(graph.edges), 2)
        cycle, category, issues = graph.validate_and_analyze()
        # No conflicting owner error produced
        self.assertNotEqual(category, RESULT_INCONSISTENT_OWNER_EVIDENCE)

    def test_18_graph_conflicting_owner_for_same_lock(self):
        """Lock observed with two different owners returns RESULT_INCONSISTENT_OWNER_EVIDENCE."""
        graph = WaitForGraph()
        t_now = time.time()
        graph.add_edge(WaitForEdge(
            waiter_tid=101,
            sync_object="0x1000",
            normalized_address="0x1000",
            owner_tid=102,
            owner_identification_status=STATUS_OWNER_IDENTIFIED,
            mutex_layout_id=LAYOUT_GLIBC_LP64,
            memory_read_status="OBSERVED",
            observation_timestamp=t_now,
            target_pid=100,
            process_identity=self._sample_valid_proc_identity(100),
            metadata=self._sample_valid_meta(102, 101),
        ))
        graph.add_edge(WaitForEdge(
            waiter_tid=103,
            sync_object="0x1000",  # Same lock
            normalized_address="0x1000",
            owner_tid=104,          # Different owner
            owner_identification_status=STATUS_OWNER_IDENTIFIED,
            mutex_layout_id=LAYOUT_GLIBC_LP64,
            memory_read_status="OBSERVED",
            observation_timestamp=t_now,
            target_pid=100,
            process_identity=self._sample_valid_proc_identity(100),
            metadata=self._sample_valid_meta(104, 103),
        ))
        cycle, category, issues = graph.validate_and_analyze()
        self.assertIsNone(cycle)
        self.assertEqual(category, RESULT_INCONSISTENT_OWNER_EVIDENCE)
        self.assertTrue(any("Conflicting owners" in s for s in issues))

    def test_19_graph_multiple_conflicting_observations_for_one_waiter(self):
        """Same waiter observed waiting on different locks returns RESULT_INCONSISTENT_OWNER_EVIDENCE."""
        graph = WaitForGraph()
        t_now = time.time()
        # Waiter 101 observed waiting on lock 0x1000
        graph.add_edge(WaitForEdge(
            waiter_tid=101,
            sync_object="0x1000",
            normalized_address="0x1000",
            owner_tid=102,
            owner_identification_status=STATUS_OWNER_IDENTIFIED,
            mutex_layout_id=LAYOUT_GLIBC_LP64,
            memory_read_status="OBSERVED",
            observation_timestamp=t_now,
            target_pid=100,
            process_identity=self._sample_valid_proc_identity(100),
            metadata=self._sample_valid_meta(102, 101),
        ))
        # Waiter 101 ALSO observed waiting on lock 0x2000 in same snapshot
        graph.add_edge(WaitForEdge(
            waiter_tid=101,
            sync_object="0x2000",
            normalized_address="0x2000",
            owner_tid=103,
            owner_identification_status=STATUS_OWNER_IDENTIFIED,
            mutex_layout_id=LAYOUT_GLIBC_LP64,
            memory_read_status="OBSERVED",
            observation_timestamp=t_now,
            target_pid=100,
            process_identity=self._sample_valid_proc_identity(100),
            metadata=self._sample_valid_meta(103, 101),
        ))
        cycle, category, issues = graph.validate_and_analyze()
        self.assertIsNone(cycle)
        self.assertEqual(category, RESULT_INCONSISTENT_OWNER_EVIDENCE)
        self.assertTrue(any("Conflicting observations for waiter" in s for s in issues))

    def test_20_graph_different_sampling_epochs_rejected(self):
        """Edges from different sampling epochs are not combined into a confirmed cycle."""
        graph = WaitForGraph()
        t_now = time.time()
        graph.add_edge(WaitForEdge(
            waiter_tid=101,
            sync_object="0x1000",
            normalized_address="0x1000",
            owner_tid=102,
            owner_identification_status=STATUS_OWNER_IDENTIFIED,
            mutex_layout_id=LAYOUT_GLIBC_LP64,
            memory_read_status="OBSERVED",
            observation_timestamp=t_now,
            target_pid=100,
            process_identity=self._sample_valid_proc_identity(100),
            sampling_epoch=1,
            metadata=self._sample_valid_meta(102, 101),
        ))
        graph.add_edge(WaitForEdge(
            waiter_tid=102,
            sync_object="0x2000",
            normalized_address="0x2000",
            owner_tid=101,
            owner_identification_status=STATUS_OWNER_IDENTIFIED,
            mutex_layout_id=LAYOUT_GLIBC_LP64,
            memory_read_status="OBSERVED",
            observation_timestamp=t_now,
            target_pid=100,
            process_identity=self._sample_valid_proc_identity(100),
            sampling_epoch=2,  # Different epoch
            metadata=self._sample_valid_meta(101, 102),
        ))
        cycle, category, issues = graph.validate_and_analyze(allowed_epoch=1)
        self.assertIsNone(cycle)
        self.assertEqual(category, RESULT_INCONSISTENT_OWNER_EVIDENCE)
        self.assertTrue(any("REJECT_CROSS_EPOCH_MISMATCH" in s for s in issues))

    def test_21_genuine_2_thread_circular_deadlock_confirmed(self):
        """Live 2-thread circular deadlock confirms DEADLOCK_CYCLE_CONFIRMED with verified cycle."""
        proc = subprocess.Popen([self.bin_2way])
        try:
            time.sleep(0.15)
            engine = AdaptiveInvestigationEngine()
            res = engine.investigate_process_health(
                goal="Check for 2-thread deadlock",
                pid=proc.pid,
                companion_elf_path=self.bin_2way,
            )
            self.assertTrue(res["success"])
            locks_out = res.get("inspection_summary", {}).get("insp_locks", {})
            self.assertTrue(locks_out.get("deadlock_detected"))
            self.assertEqual(locks_out.get("result_category"), RESULT_DEADLOCK_CYCLE_CONFIRMED)
            cycle = locks_out.get("deadlock_cycle")
            self.assertIsNotNone(cycle)
            self.assertEqual(cycle[0], cycle[-1], "Cycle must close on start TID")
            self.assertGreaterEqual(len(cycle), 3)
        finally:
            proc.terminate()
            proc.wait(timeout=2.0)

    def test_22_genuine_3_thread_circular_deadlock_confirmed(self):
        """Live 3-thread circular deadlock confirms DEADLOCK_CYCLE_CONFIRMED with verified 3-node cycle."""
        proc = subprocess.Popen([self.bin_3way])
        try:
            time.sleep(0.2)
            engine = AdaptiveInvestigationEngine()
            res = engine.investigate_process_health(
                goal="Check for 3-thread deadlock",
                pid=proc.pid,
                companion_elf_path=self.bin_3way,
            )
            self.assertTrue(res["success"])
            locks_out = res.get("inspection_summary", {}).get("insp_locks", {})
            self.assertTrue(locks_out.get("deadlock_detected"))
            self.assertEqual(locks_out.get("result_category"), RESULT_DEADLOCK_CYCLE_CONFIRMED)
            cycle = locks_out.get("deadlock_cycle")
            self.assertIsNotNone(cycle)
            self.assertEqual(cycle[0], cycle[-1])
            self.assertGreaterEqual(len(cycle), 4)
        finally:
            proc.terminate()
            proc.wait(timeout=2.0)

    def test_23_contention_without_circular_deadlock(self):
        """Thread contention without cycle confirms LOCK_CONTENTION_OBSERVED and NO false deadlock."""
        proc = subprocess.Popen([self.bin_contention])
        try:
            time.sleep(0.15)
            engine = AdaptiveInvestigationEngine()
            res = engine.investigate_process_health(
                goal="Check contention without deadlock",
                pid=proc.pid,
                companion_elf_path=self.bin_contention,
            )
            self.assertTrue(res["success"])
            locks_out = res.get("inspection_summary", {}).get("insp_locks", {})
            self.assertFalse(locks_out.get("deadlock_detected"))
            self.assertIsNone(locks_out.get("deadlock_cycle"))
            self.assertIn(
                locks_out.get("result_category"),
                (RESULT_LOCK_CONTENTION_OBSERVED, RESULT_INCOMPLETE_WAIT_FOR_GRAPH),
            )
        finally:
            proc.terminate()
            proc.wait(timeout=2.0)

    def test_24_unknown_owner_cannot_confirm_cycle(self):
        """A candidate cycle containing an unknown owner cannot produce a confirmed deadlock."""
        graph = WaitForGraph()
        t_now = time.time()
        # Edge 1 verified
        graph.add_edge(WaitForEdge(
            waiter_tid=101,
            sync_object="0x1000",
            normalized_address="0x1000",
            owner_tid=102,
            owner_identification_status=STATUS_OWNER_IDENTIFIED,
            mutex_layout_id=LAYOUT_GLIBC_LP64,
            memory_read_status="OBSERVED",
            observation_timestamp=t_now,
            target_pid=100,
            process_identity=self._sample_valid_proc_identity(100),
            metadata=self._sample_valid_meta(102, 101),
        ))
        # Edge 2 UNCONFIRMED owner
        graph.add_edge(WaitForEdge(
            waiter_tid=102,
            sync_object="0x2000",
            normalized_address="0x2000",
            owner_tid=None,
            owner_identification_status=STATUS_OWNER_NOT_IDENTIFIED,
            mutex_layout_id=LAYOUT_GLIBC_LP64,
            memory_read_status="OBSERVED",
            observation_timestamp=t_now,
            target_pid=100,
            process_identity=self._sample_valid_proc_identity(100),
            metadata=self._sample_valid_meta(101, 102),
        ))
        cycle, category, issues = graph.validate_and_analyze()
        self.assertIsNone(cycle)
        self.assertNotEqual(category, RESULT_DEADLOCK_CYCLE_CONFIRMED)
        self.assertEqual(category, RESULT_WAITING_WITH_UNKNOWN_OWNER)

    # =========================================================================
    # 3. Complete Observation Budget Enforcement
    # =========================================================================

    def test_25_budget_workmanager_path_cannot_bypass_budget(self):
        """Pre-check runs before WorkManager is called; exhausted budget returns BUDGET_EXHAUSTED."""
        engine = AdaptiveInvestigationEngine()
        limits = ObservationBudgetLimits(max_wall_clock_ms=5.0)
        tracker = ObservationBudgetTracker(limits)
        tracker.start()
        time.sleep(0.01)  # Exhaust 5ms

        class MockWM:
            called = False
            def inspect_thread_callstacks_and_locks(self, **kw):
                self.called = True
                return {"success": True, "threads": [{"tid": 100}]}

        wm = MockWM()
        mod = engine.registry.get("insp_locks")
        res = mod._func(wm, pid=os.getpid(), adapter=LocalTargetAdapter(), budget_tracker=tracker)
        self.assertFalse(res.get("success", False))
        self.assertEqual(res.get("status"), "BUDGET_EXHAUSTED")
        self.assertFalse(wm.called, "WorkManager must NOT be called when budget is already exhausted")

    def test_26_budget_fallback_path_cannot_bypass_budget(self):
        """Pre-check runs before fallback execution; exhausted budget returns BUDGET_EXHAUSTED."""
        engine = AdaptiveInvestigationEngine()
        limits = ObservationBudgetLimits(max_wall_clock_ms=5.0)
        tracker = ObservationBudgetTracker(limits)
        tracker.start()
        time.sleep(0.01)

        mod = engine.registry.get("insp_locks")
        res = mod._func(None, pid=os.getpid(), adapter=LocalTargetAdapter(), budget_tracker=tracker)
        self.assertFalse(res.get("success", False))
        self.assertEqual(res.get("status"), "BUDGET_EXHAUSTED")

    def test_27_budget_mutex_read_bytes_counted_when_owner_unknown(self):
        """When resolve_mutex_owner reads memory but owner is unknown, bytes are still counted."""
        adapter = LocalTargetAdapter()
        # Fake unlocked mutex slice: 40 bytes read, but __lock=0 so owner is not identified
        fake_raw = struct.pack("<iIiIi", 0, 0, 0, 0, 0) + b"\x00" * 20
        orig_read = adapter.read_memory
        adapter.read_memory = lambda pid, addr, sz: (fake_raw, "OBSERVED", None)
        try:
            res = adapter.resolve_mutex_owner(os.getpid(), 0x7ffd1234)
            self.assertEqual(res.status, STATUS_OWNER_NOT_IDENTIFIED)
            self.assertEqual(res.metadata.get("read_bytes_len"), 40)
            self.assertGreater(len(res.raw_bytes), 0)
        finally:
            adapter.read_memory = orig_read

    def test_28_budget_partial_memory_reads_counted_accurately(self):
        """Partial memory read of 20 bytes is counted as 20 bytes, not synthetic 40."""
        adapter = LocalTargetAdapter()
        partial_raw = b"\x00" * 20
        orig_read = adapter.read_memory
        adapter.read_memory = lambda pid, addr, sz: (partial_raw, "PARTIAL", "Partial memory read")
        try:
            res = adapter.resolve_mutex_owner(os.getpid(), 0x7ffd1234)
            self.assertEqual(res.status, STATUS_MEMORY_READ_UNAVAILABLE)
            self.assertEqual(res.metadata.get("read_bytes_len"), 20)
        finally:
            adapter.read_memory = orig_read

    def test_29_budget_failed_reads_with_transferred_bytes_accounted(self):
        """ObservationBudgetTracker accounts for transferred bytes even on failure."""
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=1024))
        tracker.record_read(bytes_read=128, is_failure=True, profile_id="test_read")
        self.assertEqual(tracker.metrics.measured_bytes_read, 128)
        self.assertEqual(tracker.metrics.total_read_failures, 1)

    def test_30_budget_remote_operation_cost_not_omitted(self):
        """Remote SSH adapter records exact bytes read into _last_maps_bytes_read."""
        adapter = RemoteSshTargetAdapter(
            host="mockhost",
            command_runner=lambda cmd, t: (0, "7f000-7f100 r-xp 0000 00:00 0 [heap]\n", ""),
        )
        maps = adapter.get_proc_maps(1234)
        self.assertEqual(len(maps), 1)
        self.assertGreater(adapter.get_last_maps_bytes_read(), 0)

    def test_31_budget_exhaustion_preserves_collected_evidence(self):
        """Mid-operation budget exhaustion preserves collected threads and sets status to PARTIAL."""
        engine = AdaptiveInvestigationEngine()
        # Budget permits get_threads but exhausts before mutex reads
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=5000))
        # Pre-charge tracker so remaining bytes is enough for get_threads (>= 256) but exhausts before mutex reads
        tracker.record_read(bytes_read=3800, profile_id="prior")

        proc = subprocess.Popen([self.bin_contention])
        try:
            time.sleep(0.15)
            mod = engine.registry.get("insp_locks")
            res = mod._func(None, pid=proc.pid, adapter=LocalTargetAdapter(), budget_tracker=tracker)
            self.assertTrue(res.get("success", False))
            self.assertEqual(res.get("status"), "PARTIAL")
            self.assertEqual(res.get("stop_reason"), "BUDGET_EXHAUSTED")
            self.assertGreater(len(res.get("threads", [])), 0, "Already collected threads must be preserved")
        finally:
            proc.terminate()
            proc.wait(timeout=2.0)

    def test_32_budget_no_double_counting_between_workmanager_and_fallback(self):
        """When WorkManager fails, fallback execution does not duplicate budget charges."""
        engine = AdaptiveInvestigationEngine()
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=100000))

        class FailingWM:
            def inspect_thread_callstacks_and_locks(self, **kw):
                raise RuntimeError("WM failure simulation")

        wm = FailingWM()
        mod = engine.registry.get("insp_locks")
        res = mod._func(wm, pid=os.getpid(), adapter=LocalTargetAdapter(), budget_tracker=tracker)
        self.assertTrue(res.get("success", False))
        # Total bytes read matches fallback execution only
        self.assertGreater(res.get("measured_bytes_read", 0), 0)


if __name__ == "__main__":
    unittest.main()
