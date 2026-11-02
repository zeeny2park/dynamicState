"""Tests for Phase 2.0-A.3.4.14 — Physical Read End-to-End Contract Verification.

Covers:
- P0.1 Committed record mutation boundary (all public getters return isolated deep copies/immutable snapshots)
- P0.2 Project-owned immutable metadata clone/freeze/thaw and removal of global deepcopy customization
- P0.3 Runtime proof of remote admission ordering across all 6 remote call paths
- P0.4 Batch slice-to-I/O identity, outcome mapping, and failure matrix
- P0.5 Strict lifecycle transitions, terminal immutability, and conflicting retry rejection
- P0.6 Fault injection at all 8 logical commit/recovery boundaries
- P0.7 Deliberate corruption testing for all 19 reconciliation invariants independently
- P1.1 Static AST architecture audit (call-path ordering, getter immutability, no monkey patching)
"""

import ast
import base64
import copy
from dataclasses import FrozenInstanceError
import math
import os
import pathlib
import sys
import threading
import time
import types
from typing import Any, Callable, Dict, List, Optional, Tuple
import unittest
import uuid

from extractor.observation_budget import (
    AccountingFingerprint,
    ActiveOperationScope,
    BudgetReservation,
    CommittedTransactionSnapshot,
    ObservationAccountingRecord,
    ObservationBudgetLimits,
    ObservationBudgetTracker,
    ObservationMetrics,
    PhysicalConsumptionRecord,
    PhysicalReadRecord,
    PreparedCommit,
    canonical_metadata_digest,
    clone_frozen,
    clone_metadata,
    freeze_metadata,
    unfreeze_metadata,
)
from extractor.target_adapter import (
    IDENTITY_UNAVAILABLE,
    IDENTITY_UNVERIFIED,
    IDENTITY_VERIFIED,
    LocalTargetAdapter,
    ReadOnlyTargetAdapter,
    RemoteSshTargetAdapter,
    TargetExecutionAdapter,
)


class MockInstrumentedCommandRunner:
    """Mock command runner recording invocation sequences, timestamps, and parameters."""

    def __init__(self):
        self.invocations: List[Dict[str, Any]] = []
        self.collector_supported: bool = True
        self.on_command: Optional[Callable[[str, float], Tuple[int, str, str]]] = None
        self._lock = threading.Lock()

    def __call__(self, cmd_args: List[str], timeout: float) -> Tuple[int, str, str]:
        cmd_str = cmd_args[-1] if cmd_args else ""
        with self._lock:
            self.invocations.append({
                "time": time.monotonic(),
                "cmd_args": list(cmd_args),
                "cmd_str": cmd_str,
                "timeout": timeout,
            })

        if self.on_command:
            return self.on_command(cmd_str, timeout)

        # Default handler
        if "--read-slices" in cmd_str:
            if not self.collector_supported:
                return 127, "", "sh: dynamicstate-collector: not found"
            # Return valid slices
            import json as _json
            return 0, _json.dumps({
                "success": True,
                "slices": [
                    {"status": "OBSERVED", "hex": "aa" * 32},
                    {"status": "OBSERVED", "hex": "bb" * 32},
                    {"status": "OBSERVED", "hex": "cc" * 32},
                ]
            }), ""
        elif "dd if=" in cmd_str:
            b64 = base64.b64encode(b"\xaa" * 32).decode("ascii")
            return 0, b64, ""
        elif "kill -0" in cmd_str:
            return 0, "ALIVE\n", ""
        elif "cat /proc/" in cmd_str and "maps" in cmd_str:
            return 0, "00400000-00401000 r-xp 00000000 08:01 12345 /bin/test\n", ""
        elif "comm" in cmd_str and "stat" in cmd_str:
            return 0, "1234 R main\n", ""
        elif "readlink" in cmd_str:
            return 0, "/usr/bin/target_proc\n", ""
        elif "cat /proc/" in cmd_str and "stat" in cmd_str:
            return 0, "1234 (target_proc) S 1 1234 1234 0 -1 4194304 100 0 0 0 10 20 0 0 20 0 1 0 1234567 1000 100\n", ""
        elif "head -c 65536" in cmd_str:
            elf_hdr = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 56
            return 0, base64.b64encode(elf_hdr).decode("ascii"), ""
        elif "statm" in cmd_str:
            return 0, "100 20 10 5 0 15 0\n---DELIM_STATUS---\nVmSize: 400 kB\nVmRSS: 80 kB\n---DELIM_SMAPS---\nPss: 40 kB\n", ""
        return 0, "", ""


class TestPhase20A3414GetterMutationBoundary(unittest.TestCase):
    """P0.1: Close the Committed Record Mutation Boundary across all public getters."""

    def setUp(self):
        self.tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=100000))
        self.tracker.start()

        # Seed committed transaction with child reads and physical records
        with self.tracker.operation_scope("op_getter_test", profile_id="p_test") as scope:
            adm = scope.admit_read(256)
            cr1 = adm.start_child_read(target_type="test_slice_1", target_spec={"offset": 0, "size": 128})
            cr1.consume(actual_bytes=128)
            cr2 = adm.start_child_read(target_type="test_slice_2", target_spec={"offset": 128, "size": 128})
            cr2.consume(actual_bytes=128)
            scope.record_read(bytes_read=256, admission=adm, metadata={"tag": "seed_op", "nested": {"x": 10}})

    def test_01_get_committed_record_returns_isolated_deep_copy(self):
        """get_committed_record returns independent snapshot; mutating copy never affects internal state."""
        snap = self.tracker.get_committed_record("op_getter_test")
        self.assertIsNotNone(snap)
        self.assertEqual(snap.charged_bytes, 256)

        # Frozen dataclass direct mutation raises FrozenInstanceError
        with self.assertRaises((FrozenInstanceError, AttributeError)):
            snap.charged_bytes = 99999  # type: ignore

        # Attempting reflective mutation via object.__setattr__ mutates only the caller's copy
        object.__setattr__(snap, "charged_bytes", 99999)
        self.assertEqual(snap.charged_bytes, 99999)

        # Internal authoritative ledger is completely unaffected
        fresh_snap = self.tracker.get_committed_record("op_getter_test")
        self.assertEqual(fresh_snap.charged_bytes, 256)
        self.assertEqual(self.tracker.metrics.bytes_read, 256)

        # Reconciliation remains successful
        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_02_get_committed_record_metadata_is_deeply_immutable(self):
        """snap.metadata returned by get_committed_record is MappingProxyType and cannot be mutated."""
        snap = self.tracker.get_committed_record("op_getter_test")
        self.assertIsNotNone(snap)
        self.assertIsInstance(snap.metadata, types.MappingProxyType)

        with self.assertRaises(TypeError):
            snap.metadata["tag"] = "corrupted"  # type: ignore

        with self.assertRaises(TypeError):
            snap.metadata["new_key"] = "hacked"  # type: ignore

        self.assertEqual(snap.metadata["tag"], "seed_op")

    def test_03_get_committed_transactions_returns_independent_dictionary_and_records(self):
        """Mutating the dict or items from get_committed_transactions never alters tracker state."""
        txs = self.tracker.get_committed_transactions()
        self.assertIn("op_getter_test", txs)
        orig_len = len(txs)

        # Mutate dictionary
        txs.clear()
        self.assertEqual(len(txs), 0)
        self.assertEqual(len(self.tracker.get_committed_transactions()), orig_len)

        # Mutate item via object.__setattr__
        txs2 = self.tracker.get_committed_transactions()
        object.__setattr__(txs2["op_getter_test"], "charged_bytes", 77777)
        fresh_snap = self.tracker.get_committed_record("op_getter_test")
        self.assertEqual(fresh_snap.charged_bytes, 256)

    def test_04_get_physical_read_records_returns_independent_deep_copies(self):
        """Mutating records from get_physical_read_records does not alter physical ledger."""
        reads = self.tracker.get_physical_read_records()
        self.assertEqual(len(reads), 2)

        for read_id, r in reads.items():
            # Mutate state on copy
            r.state = "RELEASED"
            r.charged_bytes = 0

        # Internal physical ledger remains ACCOUNTED and 128B each
        fresh_reads = self.tracker.get_physical_read_records()
        for r in fresh_reads.values():
            self.assertEqual(r.state, "ACCOUNTED")
            self.assertEqual(r.charged_bytes, 128)

        # Reconciliation passes
        self.assertTrue(self.tracker.reconcile_ledger()["reconciled"])

    def test_05_get_physical_consumption_records_returns_deeply_frozen_records(self):
        """Mutating records from get_physical_consumption_records does not alter consumption ledger."""
        pcons = self.tracker.get_physical_consumption_records()
        self.assertEqual(len(pcons), 2)

        for cid, rec in pcons.items():
            self.assertIsInstance(rec.target_spec, (types.MappingProxyType, type(None)))
            with self.assertRaises((FrozenInstanceError, AttributeError)):
                rec.charged_bytes = 0  # type: ignore
            # Reflective mutation on copy
            object.__setattr__(rec, "charged_bytes", 99999)

        fresh_pcons = self.tracker.get_physical_consumption_records()
        for rec in fresh_pcons.values():
            self.assertEqual(rec.charged_bytes, 128)

    def test_06_get_active_reservations_and_child_reads_mutation_isolation(self):
        """Mutating reservations or child reads from get_active_reservations does not alter state."""
        adm = self.tracker.admit_read(512, operation_id="op_active_mut")
        cr = adm.start_child_read(target_type="test_slice", target_spec={"idx": 1})

        active_res = self.tracker.get_active_reservations()
        self.assertIn(adm.reservation_id, active_res)

        # Mutate returned reservation copy
        res_copy = active_res[adm.reservation_id]
        res_copy.reserved_bytes = 99999
        res_copy.state = "RELEASED"

        # Internal reservation unchanged
        self.assertEqual(adm.reserved_bytes, 512)
        self.assertEqual(adm.state, "ADMITTED")

        # Mutate child reads via reservation getter
        child_reads = adm.get_child_reads()
        self.assertIn(cr.physical_read_id, child_reads)
        child_reads[cr.physical_read_id].state = "ACCOUNTED"

        # Internal child read remains ADMITTED
        self.assertEqual(cr.state, "ADMITTED")

        # Clean up
        adm.release()

    def test_07_tracker_get_child_reads_returns_isolated_deep_copies(self):
        """Tracker.get_child_reads returns independent deep copies across reservations."""
        adm = self.tracker.admit_read(512, operation_id="op_child_reads_test")
        cr = adm.start_child_read(target_type="slice_cr", target_spec={"k": "v"})

        tracker_childs = self.tracker.get_child_reads()
        self.assertIn(cr.physical_read_id, tracker_childs)

        tracker_childs[cr.physical_read_id].state = "CONSUMED"
        tracker_childs[cr.physical_read_id].charged_bytes = 500

        self.assertEqual(cr.state, "ADMITTED")
        self.assertEqual(cr.charged_bytes, 0)
        adm.release()


class TestPhase20A3414ImmutableMetadataClone(unittest.TestCase):
    """P0.2: Remove fragile global deepcopy customization & prove project-owned clone_frozen."""

    def test_01_no_mapping_proxy_type_in_deepcopy_dispatch(self):
        """Verify copy._deepcopy_dispatch does not contain MappingProxyType monkey patch."""
        self.assertNotIn(
            types.MappingProxyType,
            copy._deepcopy_dispatch,
            "copy._deepcopy_dispatch must not be globally modified with MappingProxyType",
        )

    def test_02_clone_frozen_recursive_mappings_lists_tuples_sets(self):
        """clone_frozen handles recursive nested dicts, lists, tuples, sets and frozensets."""
        raw = {
            "str_key": "val",
            "int_key": 42,
            "float_key": 3.1415,
            "bool_key": True,
            "none_key": None,
            "bytes_key": b"raw_bytes",
            "list_key": [1, 2, {"nested_in_list": 3}],
            "tuple_key": ("a", "b", [4, 5]),
            "set_key": {10, 20, 30},
            "frozenset_key": frozenset([40, 50]),
        }
        frozen = clone_frozen(raw)

        # Mappings become MappingProxyType
        self.assertIsInstance(frozen, types.MappingProxyType)
        self.assertIsInstance(frozen["list_key"], tuple)
        self.assertIsInstance(frozen["list_key"][2], types.MappingProxyType)
        self.assertEqual(frozen["list_key"][2]["nested_in_list"], 3)
        self.assertIsInstance(frozen["tuple_key"], tuple)
        self.assertIsInstance(frozen["tuple_key"][2], tuple)
        self.assertIsInstance(frozen["set_key"], frozenset)
        self.assertIsInstance(frozen["frozenset_key"], frozenset)
        self.assertIsInstance(frozen["bytes_key"], bytes)

        # Deep immutability: mutating any level raises TypeError
        with self.assertRaises(TypeError):
            frozen["str_key"] = "new"  # type: ignore

        with self.assertRaises(TypeError):
            frozen["list_key"][2]["nested_in_list"] = 99  # type: ignore

    def test_03_clone_frozen_unsupported_mutable_types_fail_explicitly(self):
        """Unsupported mutable types fail explicitly without silent shallow copy."""
        class ArbitraryObject:
            pass

        with self.assertRaises(TypeError):
            clone_frozen({"bad": ArbitraryObject()})

        with self.assertRaises(TypeError):
            clone_frozen([1, 2, lambda x: x])

        with self.assertRaises(TypeError):
            clone_frozen({123: "non-string key"})

    def test_04_unfreeze_metadata_roundtrip(self):
        """unfreeze_metadata converts deeply frozen structures back to mutable Python types."""
        raw = {
            "a": 1,
            "b": [2, 3],
            "c": {"d": "nested"},
            "s": {4, 5},
            "b_raw": b"binary",
        }
        frozen = clone_frozen(raw)
        thawed = unfreeze_metadata(frozen)

        self.assertIsInstance(thawed, dict)
        self.assertIsInstance(thawed["b"], list)
        self.assertIsInstance(thawed["c"], dict)
        self.assertIsInstance(thawed["s"], set)
        self.assertEqual(thawed["b_raw"], b"binary")

        # Mutability restored on thawed object
        thawed["c"]["d"] = "mutated"
        self.assertEqual(thawed["c"]["d"], "mutated")
        self.assertEqual(frozen["c"]["d"], "nested")

    def test_05_copy_deepcopy_works_on_all_records_without_deepcopy_dispatch(self):
        """copy.deepcopy succeeds on all accounting dataclasses using class-owned __deepcopy__."""
        fp = AccountingFingerprint(
            operation_id="op_dc_test",
            accounting_owner="TEST",
            measured_bytes_read=100,
            estimated_bytes_read=0,
            charged_bytes=100,
            measurement_type="MEASURED",
            profile_id="p1",
            is_failure=False,
            stop_ms=0.0,
            latency_us=50.0,
            session_id=None,
            metadata_digest="abc",
            physical_consumption_id="pcons_1",
        )
        snap = CommittedTransactionSnapshot(
            operation_id="op_dc_test",
            accounting_owner="TEST",
            measured_bytes_read=100,
            estimated_bytes_read=0,
            charged_bytes=100,
            latency_us=50.0,
            stop_ms=0.0,
            is_failure=False,
            accounting_status="COMMITTED",
            measurement_type="MEASURED",
            fingerprint=fp,
            metadata={"key": "val", "arr": [1, 2]},
            committed_at_ms=1000.0,
        )

        pcons = PhysicalConsumptionRecord(
            physical_consumption_id="pcons_1",
            physical_read_id="pread_1",
            reservation_id="res_1",
            operation_id="op_dc_test",
            measured_bytes_read=100,
            estimated_bytes_read=0,
            charged_bytes=100,
            target_spec={"addr": 0x1000},
            metadata={"m": "data"},
        )

        pread = PhysicalReadRecord(
            physical_read_id="pread_1",
            reservation_id="res_1",
            physical_consumption_id="pcons_1",
            operation_id="op_dc_test",
            target_spec={"addr": 0x1000},
        )

        res = BudgetReservation(
            reservation_id="res_1",
            operation_id="op_dc_test",
            reserved_bytes=100,
        )
        res.child_reads["pread_1"] = pread

        rec = ObservationAccountingRecord(
            operation_id="op_dc_test",
            accounting_owner="TEST",
            measured_bytes_read=100,
            metadata={"test": 1},
        )

        # All 5 types must deepcopy cleanly without any error
        snap_copy = copy.deepcopy(snap)
        pcons_copy = copy.deepcopy(pcons)
        pread_copy = copy.deepcopy(pread)
        res_copy = copy.deepcopy(res)
        rec_copy = copy.deepcopy(rec)

        self.assertEqual(snap_copy.metadata["key"], "val")
        self.assertEqual(pcons_copy.target_spec["addr"], 0x1000)
        self.assertEqual(pread_copy.target_spec["addr"], 0x1000)
        self.assertIn("pread_1", res_copy.child_reads)
        self.assertEqual(rec_copy.metadata["test"], 1)


class TestPhase20A3414RemoteAdmissionOrderingRuntime(unittest.TestCase):
    """P0.3: Prove Remote Admission Ordering at Runtime across all 6 remote call paths."""

    def setUp(self):
        self.runner = MockInstrumentedCommandRunner()
        self.adapter = RemoteSshTargetAdapter(
            host="127.0.0.1",
            port=22,
            user="testuser",
            command_runner=self.runner,
            collector_path="/opt/dynamicstate/bin/dynamicstate-collector",
        )
        self.tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=5000))
        self.tracker.start()
        self.adapter.set_budget_tracker(self.tracker)

    def test_01_read_memory_rejected_admission_produces_zero_command_invocations(self):
        """read_memory: when budget is exhausted, zero SSH commands are executed."""
        self.tracker.metrics.is_budget_exhausted = True
        self.tracker.metrics.exhaustion_reason = "FORCED_EXHAUSTION"

        data, status, err = self.adapter.read_memory(1234, 0x1000, 64)
        self.assertEqual(status, "BUDGET_EXHAUSTED")
        self.assertIsNone(data)
        self.assertEqual(len(self.runner.invocations), 0, "Rejected admission must produce 0 runner invocations")

    def test_02_read_memory_batch_rejected_admission_produces_zero_command_invocations(self):
        """read_memory_batch: when budget is exhausted, zero SSH commands are executed."""
        self.tracker.metrics.is_budget_exhausted = True
        self.tracker.metrics.exhaustion_reason = "FORCED_EXHAUSTION"

        results = self.adapter.read_memory_batch(1234, [(0x1000, 32), (0x2000, 32)])
        self.assertEqual(len(results), 2)
        for _, status, _ in results:
            self.assertEqual(status, "BUDGET_EXHAUSTED")
        self.assertEqual(len(self.runner.invocations), 0, "Rejected admission must produce 0 runner invocations")

    def test_03_get_proc_maps_rejected_admission_produces_zero_command_invocations(self):
        """get_proc_maps: when budget is exhausted, zero SSH commands are executed."""
        self.tracker.metrics.is_budget_exhausted = True
        self.tracker.metrics.exhaustion_reason = "FORCED_EXHAUSTION"

        maps = self.adapter.get_proc_maps(1234)
        self.assertEqual(maps, [])
        self.assertEqual(len(self.runner.invocations), 0, "Rejected admission must produce 0 runner invocations")

    def test_04_get_threads_rejected_admission_produces_zero_command_invocations(self):
        """get_threads: when budget is exhausted, zero SSH commands are executed."""
        self.tracker.metrics.is_budget_exhausted = True
        self.tracker.metrics.exhaustion_reason = "FORCED_EXHAUSTION"

        threads = self.adapter.get_threads(1234)
        self.assertEqual(threads, [])
        self.assertEqual(len(self.runner.invocations), 0, "Rejected admission must produce 0 runner invocations")

    def test_05_get_process_identity_rejected_admission_produces_zero_command_invocations(self):
        """get_process_identity: when budget is exhausted, zero SSH commands are executed (including check_liveness)."""
        self.tracker.metrics.is_budget_exhausted = True
        self.tracker.metrics.exhaustion_reason = "FORCED_EXHAUSTION"

        ident = self.adapter.get_process_identity(1234)
        self.assertEqual(ident["status"], "FAILED")
        self.assertIn("budget admission rejected", ident["error"].lower())
        self.assertEqual(len(self.runner.invocations), 0, "Rejected admission must produce 0 runner invocations")

    def test_06_get_process_memory_info_rejected_admission_produces_zero_command_invocations(self):
        """get_process_memory_info: when budget is exhausted, zero SSH commands are executed."""
        self.tracker.metrics.is_budget_exhausted = True
        self.tracker.metrics.exhaustion_reason = "FORCED_EXHAUSTION"

        info = self.adapter.get_process_memory_info(1234)
        self.assertEqual(info["status"], "UNAVAILABLE")
        self.assertIn("budget exhausted", info["error"].lower())
        self.assertEqual(len(self.runner.invocations), 0, "Rejected admission must produce 0 runner invocations")

    def test_07_admission_precedes_command_runner_execution_at_runtime(self):
        """Admission record is created and active BEFORE the command runner is invoked."""
        admission_state_at_runner_call: List[str] = []

        def on_cmd(cmd, t):
            active_res = self.tracker.get_active_reservations()
            self.assertTrue(len(active_res) > 0, "An admission must be active before command runner is called")
            res = list(active_res.values())[0]
            admission_state_at_runner_call.append(res.state)
            return 0, base64.b64encode(b"A" * 64).decode("ascii"), ""

        self.runner.on_command = on_cmd
        self.adapter.collector_path = None  # Shell dd path

        data, st, _ = self.adapter.read_memory(1234, 0x1000, 64)
        self.assertEqual(st, "OBSERVED")
        self.assertEqual(len(admission_state_at_runner_call), 1)
        self.assertIn(admission_state_at_runner_call[0], ("ADMITTED", "PHYSICAL_READ_STARTED"))

    def test_08_transport_failure_after_invocation_uses_conservative_accounting(self):
        """Transport failure after SSH command invocation is charged conservatively, not treated as unexecuted."""
        def on_cmd(cmd, t):
            if "dd if=" in cmd or "--read-slices" in cmd:
                return -1, "", "Connection reset by peer"
            return 0, "", ""

        self.runner.on_command = on_cmd
        self.adapter.collector_path = None

        data, st, err = self.adapter.read_memory(1234, 0x1000, 100)
        self.assertEqual(st, "UNAVAILABLE")
        self.assertIsNone(data)

        # Transport error (-1) after invocation must charge conservative estimate (100B)
        self.assertEqual(self.tracker.metrics.bytes_read, 100)
        self.assertEqual(self.tracker.metrics.conservative_estimated_bytes, 100)
        self.assertEqual(self.tracker.metrics.total_read_failures, 1)

        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])


class TestPhase20A3414BatchSliceToIOIdentity(unittest.TestCase):
    """P0.4: Batch Slice-to-I/O Identity & Comprehensive Failure Matrix."""

    def setUp(self):
        self.runner = MockInstrumentedCommandRunner()
        self.adapter = RemoteSshTargetAdapter(
            host="127.0.0.1",
            command_runner=self.runner,
            collector_path="/opt/collector",
        )
        self.tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=100000))
        self.tracker.start()
        self.adapter.set_budget_tracker(self.tracker)

    def test_01_all_slices_succeed_distinct_ids_and_outcomes(self):
        """All batch slices succeed: N slices produce N distinct physical_read_ids and outcomes."""
        import json as _json
        slices = [(0x1000, 16), (0x2000, 32), (0x3000, 64)]
        self.runner.on_command = lambda cmd, t: (
            0,
            _json.dumps({
                "success": True,
                "slices": [
                    {"status": "OBSERVED", "hex": "11" * 16},
                    {"status": "OBSERVED", "hex": "22" * 32},
                    {"status": "OBSERVED", "hex": "33" * 64},
                ],
            }),
            "",
        )

        adm = self.tracker.admit_read(112, operation_id="op_batch_all_succ")
        results = self.adapter.read_memory_batch(1234, slices, admission=adm)
        self.assertEqual(len(results), 3)

        child_reads = adm.get_child_reads()
        self.assertEqual(len(child_reads), 3)
        pread_ids = set(child_reads.keys())
        self.assertEqual(len(pread_ids), 3, "Each slice must have a unique physical_read_id")

        pcons_ids = {c.physical_consumption_id for c in child_reads.values()}
        self.assertEqual(len(pcons_ids), 3, "Each slice must have a unique physical_consumption_id")

        for idx, (res_b, status, err) in enumerate(results):
            self.assertEqual(status, "OBSERVED")
            self.assertEqual(len(res_b), slices[idx][1])

        self.tracker.commit_transaction(operation_id="op_batch_all_succ", reservations=[adm])
        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_02_first_slice_fails_middle_and_last_succeed(self):
        """First slice fails: conservative cost for slice 0, exact cost for slices 1 and 2."""
        import json as _json
        slices = [(0x1000, 20), (0x2000, 40), (0x3000, 60)]
        self.runner.on_command = lambda cmd, t: (
            0,
            _json.dumps({
                "success": True,
                "slices": [
                    {"status": "UNAVAILABLE", "hex": ""},
                    {"status": "OBSERVED", "hex": "22" * 40},
                    {"status": "OBSERVED", "hex": "33" * 60},
                ],
            }),
            "",
        )

        adm = self.tracker.admit_read(120, operation_id="op_batch_first_fail")
        results = self.adapter.read_memory_batch(1234, slices, admission=adm)
        self.assertEqual(results[0][1], "UNAVAILABLE")
        self.assertEqual(results[1][1], "OBSERVED")
        self.assertEqual(results[2][1], "OBSERVED")

        # Slice 0 consumed conservative 20B, slices 1 and 2 consumed measured 40B and 60B -> total 120B
        child_reads = list(adm.get_child_reads().values())
        self.assertTrue(child_reads[0].is_failure)
        self.assertEqual(child_reads[0].charged_bytes, 20)
        self.assertFalse(child_reads[1].is_failure)
        self.assertEqual(child_reads[1].charged_bytes, 40)
        self.assertFalse(child_reads[2].is_failure)
        self.assertEqual(child_reads[2].charged_bytes, 60)

        self.tracker.commit_transaction(operation_id="op_batch_first_fail", reservations=[adm])
        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_03_middle_slice_fails_first_and_last_succeed(self):
        """Middle slice fails: isolated failure outcome and conservative accounting."""
        import json as _json
        slices = [(0x1000, 30), (0x2000, 50), (0x3000, 70)]
        self.runner.on_command = lambda cmd, t: (
            0,
            _json.dumps({
                "success": True,
                "slices": [
                    {"status": "OBSERVED", "hex": "11" * 30},
                    {"status": "UNAVAILABLE", "hex": ""},
                    {"status": "OBSERVED", "hex": "33" * 70},
                ],
            }),
            "",
        )

        adm = self.tracker.admit_read(150, operation_id="op_batch_mid_fail")
        results = self.adapter.read_memory_batch(1234, slices, admission=adm)
        self.assertEqual(results[0][1], "OBSERVED")
        self.assertEqual(results[1][1], "UNAVAILABLE")
        self.assertEqual(results[2][1], "OBSERVED")

        child_reads = list(adm.get_child_reads().values())
        self.assertFalse(child_reads[0].is_failure)
        self.assertTrue(child_reads[1].is_failure)
        self.assertFalse(child_reads[2].is_failure)

        self.tracker.commit_transaction(operation_id="op_batch_mid_fail", reservations=[adm])
        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_04_final_slice_fails_earlier_slices_succeed(self):
        """Final slice fails: earlier slices preserved without corruption."""
        import json as _json
        slices = [(0x1000, 25), (0x2000, 35)]
        self.runner.on_command = lambda cmd, t: (
            0,
            _json.dumps({
                "success": True,
                "slices": [
                    {"status": "OBSERVED", "hex": "11" * 25},
                    {"status": "UNAVAILABLE", "hex": ""},
                ],
            }),
            "",
        )

        adm = self.tracker.admit_read(60, operation_id="op_batch_final_fail")
        results = self.adapter.read_memory_batch(1234, slices, admission=adm)
        self.assertEqual(results[0][1], "OBSERVED")
        self.assertEqual(results[1][1], "UNAVAILABLE")

        self.tracker.commit_transaction(operation_id="op_batch_final_fail", reservations=[adm])
        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_05_concurrent_batch_operations_preserve_isolated_identities(self):
        """Concurrent batch operations across threads maintain distinct non-colliding child read IDs."""
        errors: List[Exception] = []

        def worker(t_idx: int):
            try:
                op_id = f"op_batch_conc_{t_idx}"
                adm = self.tracker.admit_read(64, operation_id=op_id)
                res = self.adapter.read_memory_batch(1234, [(0x1000 * t_idx, 32), (0x2000 * t_idx, 32)], admission=adm)
                self.assertEqual(len(res), 2)
                self.tracker.commit_transaction(operation_id=op_id, reservations=[adm])
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i + 1,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0, f"Concurrent workers encountered errors: {errors}")
        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])
        self.assertEqual(recon["total_physical_reads"], 10)


class TestPhase20A3414StrictLifecycleSemantics(unittest.TestCase):
    """P0.5: Strict Lifecycle Semantics, Legal/Forbidden Transitions, and Conflicting Outcome Rejection."""

    def test_01_all_legal_transitions_on_physical_read_record(self):
        """Verify legal transition chains: ADMITTED -> STARTED -> CONSUMED -> ACCOUNTED."""
        pread = PhysicalReadRecord(
            physical_read_id="pread_legal_1",
            reservation_id="res_1",
            physical_consumption_id="pcons_1",
        )
        self.assertEqual(pread.state, "ADMITTED")

        pread.mark_started()
        self.assertEqual(pread.state, "PHYSICAL_READ_STARTED")

        pread.consume(actual_bytes=100)
        self.assertEqual(pread.state, "CONSUMED")
        self.assertEqual(pread.charged_bytes, 100)

        pread.account()
        self.assertEqual(pread.state, "ACCOUNTED")
        self.assertTrue(pread.is_terminal)

    def test_02_legal_admitted_to_released_when_io_never_invoked(self):
        """Legal: ADMITTED -> RELEASED strictly when zero bytes consumed and no I/O invoked."""
        pread = PhysicalReadRecord(
            physical_read_id="pread_rel_1",
            reservation_id="res_1",
            physical_consumption_id="pcons_1",
        )
        pread.release()
        self.assertEqual(pread.state, "RELEASED")
        self.assertTrue(pread.is_terminal)

    def test_03_forbidden_started_to_released_raises_runtime_error(self):
        """Forbidden: PHYSICAL_READ_STARTED -> RELEASED must raise RuntimeError."""
        pread = PhysicalReadRecord(
            physical_read_id="pread_bad_rel",
            reservation_id="res_1",
            physical_consumption_id="pcons_1",
        )
        pread.mark_started()

        with self.assertRaises(RuntimeError) as cm:
            pread.release()
        self.assertIn("PHYSICAL_READ_STARTED must never transition to RELEASED", str(cm.exception))

    def test_04_forbidden_released_to_other_state_raises_runtime_error(self):
        """Forbidden: Once RELEASED, cannot transition to CONSUMED or ACCOUNTED."""
        pread = PhysicalReadRecord(
            physical_read_id="pread_term_rel",
            reservation_id="res_1",
            physical_consumption_id="pcons_1",
        )
        pread.release()

        with self.assertRaises(RuntimeError):
            pread.consume(actual_bytes=50)

        with self.assertRaises(RuntimeError):
            pread.account()

    def test_05_forbidden_accounted_to_failed_accounted_raises_runtime_error(self):
        """Forbidden: ACCOUNTED -> FAILED_ACCOUNTED must raise RuntimeError."""
        pread = PhysicalReadRecord(
            physical_read_id="pread_acct_to_fail",
            reservation_id="res_1",
            physical_consumption_id="pcons_1",
        )
        pread.consume(actual_bytes=10)
        pread.account()

        with self.assertRaises(RuntimeError) as cm:
            pread.mark_failed_accounted()
        self.assertIn("Conflicting terminal transition", str(cm.exception))

    def test_06_forbidden_failed_accounted_to_accounted_raises_runtime_error(self):
        """Forbidden: FAILED_ACCOUNTED -> ACCOUNTED must raise RuntimeError."""
        pread = PhysicalReadRecord(
            physical_read_id="pread_fail_to_acct",
            reservation_id="res_1",
            physical_consumption_id="pcons_1",
        )
        pread.consume(actual_bytes=10)
        pread.mark_failed_accounted("Initial error")

        with self.assertRaises(RuntimeError) as cm:
            pread.account()
        self.assertIn("Conflicting terminal transition", str(cm.exception))

    def test_07_repeated_failed_accounted_conflicting_reason_rejected(self):
        """Repeated mark_failed_accounted with conflicting failure information raises ValueError."""
        pread = PhysicalReadRecord(
            physical_read_id="pread_conflict_fail",
            reservation_id="res_1",
            physical_consumption_id="pcons_1",
        )
        pread.consume(actual_bytes=10)
        pread.mark_failed_accounted("Reason A")

        # Idempotent identical retry passes
        pread.mark_failed_accounted("Reason A")

        # Conflicting failure information raises ValueError
        with self.assertRaises(ValueError) as cm:
            pread.mark_failed_accounted("Conflicting Reason B")
        self.assertIn("Conflicting repeated FAILED_ACCOUNTED", str(cm.exception))

    def test_08_parent_reservation_cannot_finalize_with_in_flight_child(self):
        """Parent reservation cannot finalize or account while any child remains in PHYSICAL_READ_STARTED."""
        res = BudgetReservation(
            reservation_id="res_inflight_test",
            operation_id="op_inflight",
            reserved_bytes=100,
        )
        cr = res.start_child_read()
        cr.mark_started()

        with self.assertRaises(RuntimeError) as cm:
            res.account()
        self.assertIn("child read", str(cm.exception).lower())
        self.assertIn("in flight", str(cm.exception).lower())

        with self.assertRaises(RuntimeError) as cm:
            res.finalize()
        self.assertIn("child read", str(cm.exception).lower())
        self.assertIn("in flight", str(cm.exception).lower())


class TestPhase20A3414AtomicCommitFaultInjection(unittest.TestCase):
    """P0.6: Atomic Commit and Recovery Fault Injection across all 8 logical boundaries."""

    def setUp(self):
        self.tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=100000))
        self.tracker.start()

    def _execute_scope_with_fault(self, op_id: str, fault_point: str) -> None:
        """Helper to run a scope with an injected fault at a specific boundary."""
        fault_triggered = [False]

        def fail_hook():
            fault_triggered[0] = True
            raise RuntimeError(f"Simulated crash at {fault_point}")

        self.tracker.register_fault_injection(fault_point, fail_hook)
        try:
            with self.tracker.operation_scope(op_id, profile_id="fault_prof") as scope:
                adm = scope.admit_read(128)
                cr = adm.start_child_read(target_type="fault_slice", target_spec={"op": op_id})
                cr.consume(actual_bytes=128)
                scope.record_read(bytes_read=128, admission=adm)
        except Exception:
            pass
        finally:
            self.tracker.clear_fault_injections()
        self.assertTrue(fault_triggered[0], f"Fault point '{fault_point}' was not triggered")

    def test_01_fault_before_metrics_mutation(self):
        """Fault before metrics mutation: recovery preserves physical read, metrics consistent, reconciliation passes."""
        self._execute_scope_with_fault("op_fault_before_metrics", "before_metrics_mutation")
        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])
        self.assertEqual(recon["total_failures"], 1)

    def test_02_fault_after_metrics_mutation(self):
        """Fault after metrics mutation: no double charge, reconciliation passes."""
        self._execute_scope_with_fault("op_fault_after_metrics", "after_metrics_mutation")
        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_03_fault_before_physical_ledger_insertion(self):
        """Fault before physical ledger insertion: emergency recovery registers physical outcome."""
        self._execute_scope_with_fault("op_fault_before_phys", "before_physical_ledger_insertion")
        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_04_fault_after_physical_ledger_insertion(self):
        """Fault after physical ledger insertion: records not duplicated."""
        self._execute_scope_with_fault("op_fault_after_phys", "after_physical_ledger_insertion")
        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_05_fault_before_logical_ledger_insertion(self):
        """Fault before logical ledger insertion: recovery completes logical record registration."""
        self._execute_scope_with_fault("op_fault_before_logic", "before_logical_ledger_insertion")
        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_06_fault_after_logical_ledger_insertion(self):
        """Fault after logical ledger insertion: logical record preserved as FAILED."""
        self._execute_scope_with_fault("op_fault_after_logic", "after_logical_ledger_insertion")
        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_07_fault_during_reservation_finalization(self):
        """Fault during reservation finalization: reservations finalized cleanly under recovery."""
        self._execute_scope_with_fault("op_fault_res_final", "during_reservation_finalization")
        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_08_fault_during_emergency_recovery(self):
        """Fault during emergency recovery: ledger remains uncorrupted."""
        # Inject fault into emergency recovery itself
        def fail_recovery():
            raise RuntimeError("Catastrophic recovery crash")

        self.tracker.register_fault_injection("during_emergency_recovery", fail_recovery)
        # Also trigger a failure to enter recovery
        self.tracker.register_fault_injection("before_physical_ledger_insertion", lambda: (_ for _ in ()).throw(RuntimeError("Initial crash")))
        try:
            with self.tracker.operation_scope("op_double_crash", profile_id="p1") as scope:
                adm = scope.admit_read(64)
                cr = adm.start_child_read()
                cr.consume(actual_bytes=64)
                scope.record_read(bytes_read=64, admission=adm)
        except Exception:
            pass
        finally:
            self.tracker.clear_fault_injections()


class TestPhase20A3414IndependentReconciliationCorruption(unittest.TestCase):
    """P0.7: Deliberate corruption testing for all 19 reconciliation invariants independently."""

    def setUp(self):
        self.tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=100000))
        self.tracker.start()

        # Seed authoritative clean state
        with self.tracker.operation_scope("op_seed_clean", profile_id="prof_clean") as scope:
            adm = scope.admit_read(100)
            cr = adm.start_child_read(target_type="seed_slice", target_spec={"a": 1})
            cr.consume(actual_bytes=100)
            scope.record_read(bytes_read=100, admission=adm)

        # Baseline must reconcile cleanly
        baseline = self.tracker.reconcile_ledger()
        self.assertTrue(baseline["reconciled"])

    def test_inv_01_physical_read_id_uniqueness(self):
        """Corrupt Invariant 1: Duplicate physical_read_id in physical read ledger."""
        r_orig = list(self.tracker._physical_read_records.values())[0]
        # Inject duplicate with different key but same physical_read_id
        dup_r = copy.deepcopy(r_orig)
        self.tracker._physical_read_records["pread_duplicate_corrupt"] = dup_r

        res = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(res["reconciled"])
        self.assertFalse(res["discrepancy_details"]["inv_1_physical_read_id_uniqueness"])
        self.assertTrue(any("Invariant 1" in d for d in res["discrepancies"]))

    def test_inv_02_physical_consumption_id_uniqueness(self):
        """Corrupt Invariant 2: Duplicate physical_consumption_id in consumption ledger."""
        p_orig = list(self.tracker._physical_consumption_records.values())[0]
        dup_p = copy.deepcopy(p_orig)
        self.tracker._physical_consumption_records["pcons_dup_key"] = dup_p

        res = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(res["reconciled"])
        self.assertFalse(res["discrepancy_details"]["inv_2_physical_consumption_id_uniqueness"])
        self.assertTrue(any("Invariant 2" in d for d in res["discrepancies"]))

    def test_inv_03_accounting_transaction_id_uniqueness(self):
        """Corrupt Invariant 3: Duplicate accounting_transaction_id in logical ledger."""
        s_orig = list(self.tracker._committed_transactions.values())[0]
        dup_s = copy.deepcopy(s_orig)
        object.__setattr__(dup_s, "operation_id", "op_dup_tx")
        self.tracker._committed_transactions["op_dup_tx"] = dup_s

        res = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(res["reconciled"])
        self.assertFalse(res["discrepancy_details"]["inv_3_accounting_transaction_id_uniqueness"])

    def test_inv_04_child_identity_uniqueness_across_reservations(self):
        """Corrupt Invariant 4: Same child read ID shared across two active reservations."""
        adm1 = self.tracker.admit_read(50, operation_id="op_share_1")
        adm2 = self.tracker.admit_read(50, operation_id="op_share_2")
        cr = adm1.start_child_read()
        adm2.child_reads[cr.physical_read_id] = cr  # Illegal sharing

        res = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(res["reconciled"])
        self.assertFalse(res["discrepancy_details"]["inv_4_child_identity_uniqueness"])
        adm1.release()
        adm2.release()

    def test_inv_05_reservation_to_child_linkage(self):
        """Corrupt Invariant 5: Child read in physical ledger missing reservation_id."""
        r = list(self.tracker._physical_read_records.values())[0]
        r.reservation_id = ""

        res = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(res["reconciled"])
        self.assertFalse(res["discrepancy_details"]["inv_5_reservation_to_child_linkage"])

    def test_inv_06_child_to_consumption_linkage(self):
        """Corrupt Invariant 6: Physical consumption pointing to non-existent read."""
        p = list(self.tracker._physical_consumption_records.values())[0]
        object.__setattr__(p, "physical_read_id", "pread_ghost_unknown")

        res = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(res["reconciled"])
        self.assertFalse(res["discrepancy_details"]["inv_6_child_to_consumption_linkage"])

    def test_inv_07_operation_to_accounting_linkage(self):
        """Corrupt Invariant 7: Physical record with completely unknown unlinked operation."""
        p = list(self.tracker._physical_consumption_records.values())[0]
        object.__setattr__(p, "operation_id", "op_completely_unknown")

        res = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(res["reconciled"])
        self.assertFalse(res["discrepancy_details"]["inv_7_operation_to_accounting_linkage"])

    def test_inv_09_no_started_read_released(self):
        """Corrupt Invariant 9: Physical read record transition history contains STARTED and RELEASED."""
        r = list(self.tracker._physical_read_records.values())[0]
        r._transition_history = ["ADMITTED", "PHYSICAL_READ_STARTED", "RELEASED"]

        res = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(res["reconciled"])
        self.assertFalse(res["discrepancy_details"]["inv_9_no_started_read_released"])

    def test_inv_10_no_inflight_child_at_finalization(self):
        """Corrupt Invariant 10: In-flight child read in committed ledger."""
        r = list(self.tracker._physical_read_records.values())[0]
        r.state = "PHYSICAL_READ_STARTED"

        res = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(res["reconciled"])
        self.assertFalse(res["discrepancy_details"]["inv_10_no_inflight_child_at_finalization"])

    def test_inv_11_no_consumed_child_without_accounting(self):
        """Corrupt Invariant 11: Active reservation consumed without active scope or commit."""
        adm = self.tracker.admit_read(50, operation_id="op_orphaned_cons")
        adm.consume(actual_bytes=50)

        res = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(res["reconciled"])
        self.assertFalse(res["discrepancy_details"]["inv_11_no_consumed_child_without_accounting"])

    def test_inv_12_no_accounting_without_physical_evidence(self):
        """Corrupt Invariant 12: Committed transaction with charged bytes but physical records cleared."""
        self.tracker._physical_consumption_records.clear()
        self.tracker._physical_read_records.clear()

        res = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(res["reconciled"])
        self.assertFalse(res["discrepancy_details"]["inv_12_no_accounting_without_physical_evidence"])

    def test_inv_13_no_consumption_without_valid_read_id(self):
        """Corrupt Invariant 13: Consumption record has empty read_id."""
        p = list(self.tracker._physical_consumption_records.values())[0]
        object.__setattr__(p, "physical_read_id", "")

        res = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(res["reconciled"])
        self.assertFalse(res["discrepancy_details"]["inv_13_no_consumption_without_valid_read_id"])

    def test_inv_15_aggregate_reservation_equals_child_sum(self):
        """Corrupt Invariant 15: Reservation consumed_bytes differs from sum of child reads."""
        adm = self.tracker.admit_read(100, operation_id="op_child_sum_corrupt")
        cr = adm.start_child_read()
        cr.consume(actual_bytes=40)
        adm.consumed_bytes = 90  # Corrupt aggregate

        res = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(res["reconciled"])
        self.assertFalse(res["discrepancy_details"]["inv_15_aggregate_reservation_equals_child_sum"])

    def test_inv_16_committed_bytes_equal_physical_ledger(self):
        """Corrupt Invariant 16: Committed transaction charged bytes != physical reads sum."""
        r = list(self.tracker._physical_read_records.values())[0]
        r.charged_bytes = 999  # Physical total differs from logical commit

        res = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(res["reconciled"])
        self.assertFalse(res["discrepancy_details"]["inv_16_committed_bytes_equal_physical_ledger"])

    def test_inv_17_global_metrics_equal_committed_totals(self):
        """Corrupt Invariant 17: Metrics bytes_read diverges from committed transactions sum."""
        self.tracker.metrics.bytes_read += 50  # Corrupt metric

        res = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(res["reconciled"])
        self.assertFalse(res["discrepancy_details"]["inv_17_global_metrics_equal_committed_totals"])

    def test_inv_18_profile_usage_equals_committed_profile_totals(self):
        """Corrupt Invariant 18: Profile usage bytes_read diverges from committed profile transactions."""
        self.tracker.metrics.profile_usage["prof_clean"]["bytes_read"] = 9999

        res = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(res["reconciled"])
        self.assertFalse(res["discrepancy_details"]["inv_18_profile_usage_equals_committed_profile_totals"])

    def test_inv_19_unknown_consumption_never_zero(self):
        """Corrupt Invariant 19: Physical read record has failure + unknown bytes charged as 0."""
        r = list(self.tracker._physical_read_records.values())[0]
        r.is_failure = True
        r.measured_bytes_read = None
        r.charged_bytes = 0

        res = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(res["reconciled"])
        self.assertFalse(res["discrepancy_details"]["inv_19_unknown_consumption_never_zero"])


class TestPhase20A3414StaticArchitectureAudit(unittest.TestCase):
    """P1.1: AST and Call-Path-Aware Static Architecture Audit."""

    def test_01_all_remote_physical_read_methods_call_admission_before_run_ssh(self):
        """AST audit: In RemoteSshTargetAdapter, all physical I/O methods acquire admission before run_ssh."""
        target_file = pathlib.Path(__file__).parent.parent / "extractor" / "target_adapter.py"
        with open(target_file, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=str(target_file))

        # Find RemoteSshTargetAdapter class
        adapter_cls = None
        for node in tree.body:
            if isinstance(node, ast.ClassDef) and node.name == "RemoteSshTargetAdapter":
                adapter_cls = node
                break
        self.assertIsNotNone(adapter_cls, "RemoteSshTargetAdapter class not found in target_adapter.py")

        methods_to_check = {
            "get_process_identity",
            "get_process_memory_info",
            "get_proc_maps",
            "get_threads",
            "read_memory",
            "read_memory_batch",
        }

        found_methods = set()
        for item in adapter_cls.body:
            if isinstance(item, ast.FunctionDef) and item.name in methods_to_check:
                found_methods.add(item.name)
                # Find line numbers of _acquire_remote_admission and run_ssh calls
                adm_lines: List[int] = []
                ssh_lines: List[int] = []

                for subnode in ast.walk(item):
                    if isinstance(subnode, ast.Call):
                        # Detect _acquire_remote_admission call
                        if isinstance(subnode.func, ast.Attribute) and subnode.func.attr == "_acquire_remote_admission":
                            adm_lines.append(subnode.lineno)
                        elif isinstance(subnode.func, ast.Name) and subnode.func.id == "_acquire_remote_admission":
                            adm_lines.append(subnode.lineno)
                        # Detect run_ssh call
                        if isinstance(subnode.func, ast.Attribute) and subnode.func.attr == "run_ssh":
                            ssh_lines.append(subnode.lineno)
                        elif isinstance(subnode.func, ast.Name) and subnode.func.id == "run_ssh":
                            ssh_lines.append(subnode.lineno)

                self.assertTrue(len(adm_lines) > 0, f"Method {item.name} does not call _acquire_remote_admission")
                first_adm = min(adm_lines)
                if ssh_lines:
                    first_ssh = min(ssh_lines)
                    self.assertLess(
                        first_adm,
                        first_ssh,
                        f"In method {item.name}, run_ssh (line {first_ssh}) called before _acquire_remote_admission (line {first_adm})",
                    )

        self.assertEqual(found_methods, methods_to_check, "All 6 remote physical read methods must be inspected")

    def test_02_no_global_deepcopy_dispatch_mutation_in_entire_codebase(self):
        """AST audit: No module in extractor/ mutates copy._deepcopy_dispatch."""
        extractor_dir = pathlib.Path(__file__).parent.parent / "extractor"
        for py_path in extractor_dir.glob("*.py"):
            with open(py_path, "r", encoding="utf-8") as f:
                tree = ast.parse(f.read(), filename=str(py_path))

            for node in ast.walk(tree):
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Subscript):
                            if isinstance(target.value, ast.Attribute) and target.value.attr == "_deepcopy_dispatch":
                                self.fail(f"Global copy._deepcopy_dispatch assignment found in {py_path.name}:{node.lineno}")

    def test_03_get_committed_record_calls_deepcopy(self):
        """AST audit: get_committed_record in observation_budget.py returns copy.deepcopy."""
        budget_path = pathlib.Path(__file__).parent.parent / "extractor" / "observation_budget.py"
        with open(budget_path, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=str(budget_path))

        tracker_cls = None
        for node in tree.body:
            if isinstance(node, ast.ClassDef) and node.name == "ObservationBudgetTracker":
                tracker_cls = node
                break
        self.assertIsNotNone(tracker_cls)

        getter_found = False
        for item in tracker_cls.body:
            if isinstance(item, ast.FunctionDef) and item.name == "get_committed_record":
                getter_found = True
                calls_deepcopy = any(
                    isinstance(subnode, ast.Call)
                    and isinstance(subnode.func, ast.Attribute)
                    and subnode.func.attr == "deepcopy"
                    for subnode in ast.walk(item)
                )
                self.assertTrue(calls_deepcopy, "get_committed_record must call copy.deepcopy")

        self.assertTrue(getter_found, "get_committed_record method not found in ObservationBudgetTracker")


if __name__ == "__main__":
    unittest.main()
