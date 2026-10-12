"""Comprehensive tests for:
1. Capture safety: pre-existing stop state preservation, capture-induced stop/resume, unconfirmed stop reporting.
2. PID reuse mitigation: Linux pidfd_open / pidfd_send_signal vs starttime fallback, target exit, resource cleanup.
3. Snapshot diff accuracy: strict event kind counting in StateDiff.summary.
4. Evidence ledger schema validation: validation rules, rejection of invalid IDs/types/natures, cycle detection, DAGs.
"""

import errno
import os
import signal
import subprocess
import sys
import time
import unittest

from extractor.capture_backend import (
    ProcessVmCaptureBackend,
    ProcfsCaptureBackend,
    ProcessTargetHandle,
    CaptureSafetyPolicy,
    _get_process_state,
    _get_threads_state,
)
from extractor.capture_plan import CapturePlan, CaptureMode
from extractor.state_diff import StateDiffEngine
from extractor.evidence_ledger import (
    EvidenceLedger,
    EvidenceRecord,
    EVIDENCE_TYPE_OBJECT_STATE,
    EVIDENCE_TYPE_RUNTIME_IDENTITY,
    EVIDENCE_TYPE_CAPTURE_QUALITY,
    EVIDENCE_TYPE_DIAGNOSTIC,
    EVIDENCE_TYPE_STATIC_LINK,
    NATURE_OBSERVATION,
    NATURE_INFERENCE,
    NATURE_HYPOTHESIS,
    VALID_EVIDENCE_TYPES,
    VALID_NATURES,
)


def _make_snapshot(objects, function="process_packet", pc="0x401200", thread_id=1):
    return {
        "schema_version": "0.3",
        "snapshot": {"snapshot_id": "S001", "pid": 1234, "binary": "./sample"},
        "execution": {
            "threads": [
                {
                    "thread_id": thread_id,
                    "frames": [{"level": 0, "function": function, "pc": pc}]
                }
            ]
        },
        "persistent": {"objects": objects}
    }


def _make_obj(object_id, address, typ, fields):
    return {"object_id": object_id, "address": address, "type": typ, "fields": fields}


class TestCaptureSafetyPreexistingStop(unittest.TestCase):
    """Test capture safety regarding pre-existing stopped processes."""

    def setUp(self):
        # Spawn a python child process that stays alive
        self.proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.pid = self.proc.pid
        time.sleep(0.05)

    def tearDown(self):
        try:
            self.proc.kill()
            self.proc.wait(timeout=1)
        except Exception:
            pass

    def test_preexisting_stopped_process_preserves_stop_and_skips_sigcont(self):
        """If a target is already stopped before capture:
        - SIGSTOP must not cause new suspension
        - SIGCONT must NOT be sent upon completion
        - Target must remain stopped after capture completes
        - Consistency classification must be PREEXISTING_STOPPED
        """
        # Stop the child process manually before capture
        os.kill(self.pid, signal.SIGSTOP)
        time.sleep(0.05)

        # Verify child is actually in STOPPED state
        st = _get_process_state(self.pid)
        self.assertTrue(st["is_stopped"], f"Process should be stopped, got {st}")

        backend = ProcessVmCaptureBackend()
        if not backend.is_available(self.pid):
            backend = ProcfsCaptureBackend()

        plan = CapturePlan(mode=CaptureMode.FULL.value)
        policy = CaptureSafetyPolicy(max_stop_time_ms=50.0)

        snap = backend.capture(self.pid, plan=plan, policy=policy)

        # Verify snapshot metadata
        obs_meta = snap.observation_metadata
        self.assertTrue(obs_meta.get("was_already_stopped"), "Snapshot should record was_already_stopped=True")
        self.assertFalse(obs_meta.get("suspension_caused_by_capture"), "Capture did not cause suspension")
        self.assertEqual(obs_meta.get("stop_mechanism"), "PREEXISTING_STOP_PRESERVED")
        self.assertEqual(obs_meta.get("consistency_classification"), "PREEXISTING_STOPPED")

        state_machine = obs_meta.get("stop_state_machine", {})
        self.assertIn("PREEXISTING_STOP_PRESERVED", state_machine.get("states", []))
        self.assertIn("PREEXISTING_STOP_RETAINED", state_machine.get("states", []))
        self.assertNotIn("RESUME_REQUESTED", state_machine.get("states", []))

        # Verify the process is STILL STOPPED!
        post_st = _get_process_state(self.pid)
        self.assertTrue(post_st["is_stopped"], f"Process should remain stopped after capture, got {post_st}")

    def test_running_process_is_stopped_and_resumed_by_capture(self):
        """Normal running target:
        - Capture induces stop (suspension_caused_by_capture is True)
        - Target is stopped and resumed (RESUME_CONFIRMED)
        - Consistency is SIGNAL_STOPPED
        - Process is running after capture completes
        """
        st_initial = _get_process_state(self.pid)
        self.assertFalse(st_initial["is_stopped"])

        backend = ProcessVmCaptureBackend()
        if not backend.is_available(self.pid):
            backend = ProcfsCaptureBackend()

        plan = CapturePlan(mode=CaptureMode.FULL.value)
        policy = CaptureSafetyPolicy(max_stop_time_ms=50.0)

        snap = backend.capture(self.pid, plan=plan, policy=policy)

        obs_meta = snap.observation_metadata
        self.assertFalse(obs_meta.get("was_already_stopped"))
        self.assertTrue(obs_meta.get("suspension_caused_by_capture"))
        self.assertEqual(obs_meta.get("stop_mechanism"), "SIGSTOP")
        self.assertEqual(obs_meta.get("consistency_classification"), "SIGNAL_STOPPED")

        state_machine = obs_meta.get("stop_state_machine", {})
        self.assertIn("STOP_CONFIRMED", state_machine.get("states", []))
        self.assertIn("RESUME_REQUESTED", state_machine.get("states", []))
        self.assertIn("RESUME_CONFIRMED", state_machine.get("states", []))

        # Process should be running
        time.sleep(0.05)
        post_st = _get_process_state(self.pid)
        self.assertFalse(post_st["is_stopped"], f"Process should be running after resume, got {post_st}")

    def test_zero_stop_mode_does_not_stop_process(self):
        """In ZERO_STOP mode:
        - Process is NOT stopped
        - Consistency classification is NON_ATOMIC
        - stop_mechanism is NONE
        """
        backend = ProcessVmCaptureBackend()
        if not backend.is_available(self.pid):
            backend = ProcfsCaptureBackend()

        plan = CapturePlan(mode=CaptureMode.ZERO_STOP.value)
        snap = backend.capture(self.pid, plan=plan)

        obs_meta = snap.observation_metadata
        self.assertFalse(obs_meta.get("was_already_stopped"))
        self.assertFalse(obs_meta.get("suspension_caused_by_capture"))
        self.assertEqual(obs_meta.get("stop_mechanism"), "NONE")
        self.assertEqual(obs_meta.get("consistency_classification"), "NON_ATOMIC")
        self.assertEqual(snap.provenance.get("snapshot_consistency"), "NON_ATOMIC")


class TestPidReuseMitigation(unittest.TestCase):
    """Test ProcessTargetHandle, pidfd support, and deterministic fallback testing."""

    def setUp(self):
        self.proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.pid = self.proc.pid
        time.sleep(0.05)

    def tearDown(self):
        try:
            self.proc.kill()
            self.proc.wait(timeout=1)
        except Exception:
            pass

    def test_pidfd_path_when_supported(self):
        """On supported kernels, ProcessTargetHandle opens a pidfd and sends signals safely."""
        handle = ProcessTargetHandle(self.pid, force_fallback=False)
        handle.open()
        try:
            diags = handle.get_diagnostics()
            if handle.pidfd_supported:
                self.assertTrue(handle.pidfd_used)
                self.assertEqual(diags["mitigation_mechanism"], "PIDFD")
                self.assertIsNone(diags["fallback_caveat"])
                self.assertIsNotNone(handle.pidfd)

                # Verify identity using pidfd
                is_same, status = handle.verify_identity()
                self.assertTrue(is_same)
                self.assertEqual(status, "PIDFD_VERIFIED")

                # Send signal 0
                sig_ok, err = handle.send_signal(0)
                self.assertTrue(sig_ok)
                self.assertIsNone(err)
        finally:
            handle.close()
            self.assertTrue(handle.closed)
            self.assertIsNone(handle.pidfd)

    def test_force_fallback_path_exercises_starttime_verification(self):
        """When force_fallback=True is set, pidfd is bypassed and /proc/<pid>/stat starttime verification is used."""
        handle = ProcessTargetHandle(self.pid, force_fallback=True)
        handle.open()
        try:
            self.assertFalse(handle.pidfd_used)
            self.assertIsNone(handle.pidfd)
            diags = handle.get_diagnostics()
            self.assertEqual(diags["mitigation_mechanism"], "STAT_STARTTIME_CHECK_FALLBACK")
            self.assertIn("Fallback starttime verification cannot guarantee complete immunity", diags["fallback_caveat"])

            # Verify identity using starttime fallback
            is_same, status = handle.verify_identity()
            self.assertTrue(is_same)
            self.assertEqual(status, "FALLBACK_VERIFIED")

            # Send signal 0
            sig_ok, err = handle.send_signal(0)
            self.assertTrue(sig_ok)
            self.assertIsNone(err)
        finally:
            handle.close()
            self.assertTrue(handle.closed)

    def test_fallback_detects_pid_reuse(self):
        """If target starttime changes (simulating PID reuse), fallback rejects signal and identity verification."""
        handle = ProcessTargetHandle(self.pid, force_fallback=True)
        handle.open()
        try:
            # Tamper initial identity to simulate that the original process died and a new one took its PID
            handle.initial_identity["starttime"] = "9999999999"

            # Verify identity should report PID_REUSED
            is_same, status = handle.verify_identity()
            self.assertFalse(is_same)
            self.assertEqual(status, "PID_REUSED")

            # send_signal should abort with PID_REUSED
            sig_ok, err = handle.send_signal(signal.SIGCONT)
            self.assertFalse(sig_ok)
            self.assertEqual(err, "PID_REUSED")
        finally:
            handle.close()

    def test_handle_detects_target_exit(self):
        """If target process exits, handle reports TARGET_EXITED."""
        # Kill the process
        self.proc.kill()
        self.proc.wait()

        handle = ProcessTargetHandle(self.pid, force_fallback=True)
        with self.assertRaises(ProcessLookupError):
            handle.open()


class TestSnapshotDiffStatisticsAccuracy(unittest.TestCase):
    """Verify that StateDiffEngine counts only corresponding event kinds."""

    def test_field_added_does_not_increment_objects_created(self):
        """field_added must increment fields_added, but NEVER increment objects_created."""
        before_state = _make_snapshot([
            _make_obj("obj_0001", "0x1000", "Session", [{"name": "retry", "value": 2}])
        ])
        after_state = _make_snapshot([
            _make_obj("obj_0001", "0x1000", "Session", [
                {"name": "retry", "value": 2},
                {"name": "timeout", "value": 30}  # added field
            ])
        ])

        diff_engine = StateDiffEngine()
        result = diff_engine.diff(before_state, after_state)
        summary = result.summary

        # Strict separation check:
        self.assertEqual(summary["objects_created"], 0, "objects_created must NOT be incremented by field_added!")
        self.assertEqual(summary["objects_removed"], 0)
        self.assertEqual(summary["fields_added"], 1, "fields_added must be 1")
        self.assertEqual(summary["fields_unavailable"], 0)

    def test_field_unavailable_does_not_increment_objects_removed(self):
        """field_unavailable (absent field) must increment fields_unavailable, but NEVER objects_removed."""
        before_state = _make_snapshot([
            _make_obj("obj_0001", "0x1000", "Session", [
                {"name": "retry", "value": 2},
                {"name": "token", "value": "abc"}
            ])
        ])
        after_state = _make_snapshot([
            _make_obj("obj_0001", "0x1000", "Session", [
                {"name": "retry", "value": 2}  # token removed / unavailable
            ])
        ])

        diff_engine = StateDiffEngine()
        result = diff_engine.diff(before_state, after_state)
        summary = result.summary

        self.assertEqual(summary["objects_removed"], 0, "objects_removed must NOT be incremented by field_unavailable!")
        self.assertEqual(summary["objects_created"], 0)
        self.assertEqual(summary["fields_unavailable"], 1)

    def test_availability_change_does_not_increment_objects_removed(self):
        """availability_change must increment availability_changes, but NEVER objects_removed."""
        before_state = _make_snapshot([
            _make_obj("obj_0001", "0x1000", "Session", [{"name": "foo", "value": 1, "availability": "available"}])
        ])
        after_state = _make_snapshot([
            _make_obj("obj_0001", "0x1000", "Session", [{"name": "foo", "value": None, "availability": "unavailable"}])
        ])

        diff_engine = StateDiffEngine()
        result = diff_engine.diff(before_state, after_state)
        summary = result.summary

        self.assertEqual(summary["objects_removed"], 0, "objects_removed must NOT be incremented by availability_change!")
        self.assertEqual(summary["objects_created"], 0)
        self.assertEqual(summary["availability_changes"], 1)

    def test_actual_object_creation_and_removal(self):
        """Creating an object increments objects_created; removing increments objects_removed."""
        before_state = _make_snapshot([
            _make_obj("obj_0001", "0x1000", "Foo", [])
        ])
        after_state = _make_snapshot([
            _make_obj("obj_0002", "0x2000", "Bar", [])
        ])

        diff_engine = StateDiffEngine()
        result = diff_engine.diff(before_state, after_state)
        summary = result.summary

        self.assertEqual(summary["objects_created"], 1)
        self.assertEqual(summary["objects_removed"], 1)
        self.assertEqual(summary["fields_added"], 0)
        self.assertEqual(summary["fields_unavailable"], 0)

    def test_missing_address_or_type_confidence_uncertain(self):
        """Objects with missing address or type get identity_confidence: 'uncertain'."""
        before_state = _make_snapshot([])
        after_state = _make_snapshot([
            _make_obj("obj_0001", None, "", [])
        ])

        diff_engine = StateDiffEngine()
        result = diff_engine.diff(before_state, after_state)
        events = result.changes
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["identity_confidence"], "uncertain")
        self.assertEqual(result.summary["identity_ambiguities"], 1)

    def test_reference_change_vs_value_change(self):
        """Distinguish pointer/reference changes from primitive value changes."""
        before_state = _make_snapshot([
            _make_obj("obj_0001", "0x1000", "Node", [
                {"name": "val", "value": 10},
                {"name": "next", "value": "0x2000", "object_ref": "obj_0002"},
            ])
        ])
        after_state = _make_snapshot([
            _make_obj("obj_0001", "0x1000", "Node", [
                {"name": "val", "value": 20},  # value_change
                {"name": "next", "value": "0x3000", "object_ref": "obj_0003"},  # reference_change
            ])
        ])

        diff_engine = StateDiffEngine()
        result = diff_engine.diff(before_state, after_state)
        summary = result.summary

        self.assertEqual(summary["value_changes"], 1)
        self.assertEqual(summary["reference_changes"], 1)
        self.assertEqual(summary["objects_created"], 0)
        self.assertEqual(summary["objects_removed"], 0)
        self.assertEqual(summary["field_level_changes"], 2)

    def test_empty_and_identical_snapshots(self):
        """Diffing empty or identical snapshots produces 0 changes."""
        diff_engine = StateDiffEngine()

        # None inputs
        res_none = diff_engine.diff(None, None)
        self.assertEqual(len(res_none.changes), 0)
        self.assertEqual(res_none.summary["total_changes"], 0)

        # Empty dicts
        res_empty = diff_engine.diff({}, {})
        self.assertEqual(len(res_empty.changes), 0)

        # Identical snapshots
        snap = _make_snapshot([_make_obj("obj_0001", "0x1000", "A", [{"name": "x", "value": 1}])])
        res_identical = diff_engine.diff(snap, snap)
        self.assertEqual(len(res_identical.changes), 0)
        self.assertEqual(res_identical.summary["total_changes"], 0)

    def test_serialization_round_trip(self):
        """StateDiff to_dict produces valid dictionary with all aggregate fields."""
        before = _make_snapshot([_make_obj("obj_0001", "0x1000", "A", [{"name": "x", "value": 1}])])
        after = _make_snapshot([_make_obj("obj_0001", "0x1000", "A", [{"name": "x", "value": 2}])])

        diff_engine = StateDiffEngine()
        res = diff_engine.diff(before, after)
        d = res.to_dict()

        self.assertIn("summary", d)
        self.assertIn("changes", d)
        self.assertIn("object_lifecycle_changes", d["summary"])
        self.assertIn("field_level_changes", d["summary"])
        self.assertIn("observation_availability_changes", d["summary"])
        self.assertIn("identity_ambiguities", d["summary"])



class TestEvidenceLedgerSchemaValidation(unittest.TestCase):
    """Test EvidenceRecord and EvidenceLedger schema validation."""

    def test_reject_empty_or_whitespace_evidence_id(self):
        """EvidenceRecord must reject empty string or whitespace evidence_id."""
        with self.assertRaises(ValueError):
            EvidenceRecord(
                evidence_id="",
                evidence_type=EVIDENCE_TYPE_OBJECT_STATE,
                nature=NATURE_OBSERVATION,
            )

        with self.assertRaises(ValueError):
            EvidenceRecord(
                evidence_id="   ",
                evidence_type=EVIDENCE_TYPE_OBJECT_STATE,
                nature=NATURE_OBSERVATION,
            )

    def test_reject_invalid_evidence_type(self):
        """EvidenceRecord must reject evidence_type not in VALID_EVIDENCE_TYPES."""
        with self.assertRaises(ValueError) as ctx:
            EvidenceRecord(
                evidence_id="EV_001",
                evidence_type="INVALID_TYPE_XYZ",
                nature=NATURE_OBSERVATION,
            )
        self.assertIn("Invalid evidence_type", str(ctx.exception))

    def test_reject_invalid_nature(self):
        """EvidenceRecord must reject nature not in VALID_NATURES."""
        with self.assertRaises(ValueError) as ctx:
            EvidenceRecord(
                evidence_id="EV_001",
                evidence_type=EVIDENCE_TYPE_OBJECT_STATE,
                nature="FABRICATED_OPINION",
            )
        self.assertIn("Invalid evidence nature", str(ctx.exception))

    def test_reject_non_list_parent_evidence_ids(self):
        """parent_evidence_ids must be a list of strings."""
        with self.assertRaises(TypeError):
            EvidenceRecord(
                evidence_id="EV_001",
                evidence_type=EVIDENCE_TYPE_OBJECT_STATE,
                nature=NATURE_OBSERVATION,
                parent_evidence_ids="EV_000",  # String instead of list
            )

    def test_backward_compatibility_with_case_insensitive_legacy(self):
        """from_dict normalizes lowercase legacy types/natures."""
        data = {
            "evidence_id": "EV_LEGACY",
            "evidence_type": "object_state",
            "nature": "observation",
            "confidence": 0.9,
        }
        rec = EvidenceRecord.from_dict(data)
        self.assertEqual(rec.evidence_type, EVIDENCE_TYPE_OBJECT_STATE)
        self.assertEqual(rec.nature, NATURE_OBSERVATION)

    def test_duplicate_evidence_id_rejected(self):
        """EvidenceLedger must reject duplicate record IDs."""
        ledger = EvidenceLedger()
        rec1 = EvidenceRecord(
            evidence_id="EV_DUP",
            evidence_type=EVIDENCE_TYPE_OBJECT_STATE,
            nature=NATURE_OBSERVATION,
        )
        rec2 = EvidenceRecord(
            evidence_id="EV_DUP",
            evidence_type=EVIDENCE_TYPE_RUNTIME_IDENTITY,
            nature=NATURE_OBSERVATION,
        )
        ledger.add_record(rec1)
        with self.assertRaises(ValueError):
            ledger.add_record(rec2)

    def test_cycle_detection_without_infinite_recursion(self):
        """Verifies cycle detection handles circular parent references cleanly."""
        ledger = EvidenceLedger()

        # Build a circular chain: A -> B -> C -> A
        rec_a = EvidenceRecord(
            evidence_id="EV_A",
            evidence_type=EVIDENCE_TYPE_OBJECT_STATE,
            nature=NATURE_OBSERVATION,
            parent_evidence_ids=["EV_C"],
        )
        rec_b = EvidenceRecord(
            evidence_id="EV_B",
            evidence_type=EVIDENCE_TYPE_OBJECT_STATE,
            nature=NATURE_OBSERVATION,
            parent_evidence_ids=["EV_A"],
        )
        rec_c = EvidenceRecord(
            evidence_id="EV_C",
            evidence_type=EVIDENCE_TYPE_OBJECT_STATE,
            nature=NATURE_OBSERVATION,
            parent_evidence_ids=["EV_B"],
        )

        ledger.add_record(rec_a)
        ledger.add_record(rec_b)
        ledger.add_record(rec_c)

        # trace_provenance_chain must not enter an infinite loop and detect cycle
        chain_a = ledger.trace_provenance_chain("EV_A")
        # Cycle detected step is appended
        statuses = [step.get("status") for step in chain_a]
        self.assertIn("CYCLE_DETECTED", statuses)

    def test_common_parent_dag_diamond(self):
        """Diamond DAG (root -> left/right -> leaf) must be traversed without false cycles."""
        ledger = EvidenceLedger()

        rec_root = EvidenceRecord(
            evidence_id="EV_ROOT",
            evidence_type=EVIDENCE_TYPE_OBJECT_STATE,
            nature=NATURE_OBSERVATION,
        )
        rec_left = EvidenceRecord(
            evidence_id="EV_LEFT",
            evidence_type=EVIDENCE_TYPE_STATIC_LINK,
            nature=NATURE_OBSERVATION,
            parent_evidence_ids=["EV_ROOT"],
        )
        rec_right = EvidenceRecord(
            evidence_id="EV_RIGHT",
            evidence_type=EVIDENCE_TYPE_STATIC_LINK,
            nature=NATURE_OBSERVATION,
            parent_evidence_ids=["EV_ROOT"],
        )
        rec_leaf = EvidenceRecord(
            evidence_id="EV_LEAF",
            evidence_type=EVIDENCE_TYPE_DIAGNOSTIC,
            nature=NATURE_INFERENCE,
            parent_evidence_ids=["EV_LEFT", "EV_RIGHT"],
        )

        ledger.add_record(rec_root)
        ledger.add_record(rec_left)
        ledger.add_record(rec_right)
        ledger.add_record(rec_leaf)

        chain = ledger.trace_provenance_chain("EV_LEAF")
        # Must resolve leaf, left, right, root without reporting false cycle
        statuses = [step.get("status") for step in chain]
        self.assertNotIn("CYCLE_DETECTED", statuses)
        resolved_ids = [step.get("evidence_id") for step in chain if step.get("status") == "RESOLVED"]
        self.assertCountEqual(resolved_ids, ["EV_LEAF", "EV_LEFT", "EV_RIGHT", "EV_ROOT"])

    def test_reject_self_referencing_parent(self):
        """EvidenceRecord and EvidenceLedger reject self-referential lineage links (A -> A)."""
        with self.assertRaises(ValueError) as ctx:
            EvidenceRecord(
                evidence_id="EV_SELF",
                evidence_type=EVIDENCE_TYPE_OBJECT_STATE,
                nature=NATURE_OBSERVATION,
                parent_evidence_ids=["EV_SELF"],
            )
        self.assertIn("Self-reference detected", str(ctx.exception))

    def test_reject_empty_or_whitespace_session_and_finding_id(self):
        """EvidenceRecord rejects empty or whitespace session_id and finding_id."""
        with self.assertRaises(ValueError):
            EvidenceRecord(
                evidence_id="EV_1",
                evidence_type=EVIDENCE_TYPE_OBJECT_STATE,
                nature=NATURE_OBSERVATION,
                session_id="",
            )

        with self.assertRaises(ValueError):
            EvidenceRecord(
                evidence_id="EV_2",
                evidence_type=EVIDENCE_TYPE_OBJECT_STATE,
                nature=NATURE_OBSERVATION,
                finding_id="   ",
            )

    def test_unresolved_parent_reported_in_provenance_chain(self):
        """Missing parent records are reported as UNRESOLVED_PARENT in provenance chain."""
        ledger = EvidenceLedger()
        rec = EvidenceRecord(
            evidence_id="EV_CHILD",
            evidence_type=EVIDENCE_TYPE_OBJECT_STATE,
            nature=NATURE_OBSERVATION,
            parent_evidence_ids=["EV_MISSING_PARENT"],
        )
        ledger.add_record(rec)

        chain = ledger.trace_provenance_chain("EV_CHILD")
        statuses = [step.get("status") for step in chain]
        self.assertIn("UNRESOLVED_PARENT", statuses)
        unresolved = [step for step in chain if step.get("status") == "UNRESOLVED_PARENT"]
        self.assertEqual(unresolved[0]["evidence_id"], "EV_MISSING_PARENT")

    def test_deterministic_traversal_order(self):
        """Multiple parents are traversed in deterministic sorted order."""
        ledger = EvidenceLedger()
        for pid in ["EV_Z", "EV_A", "EV_M"]:
            ledger.add_record(EvidenceRecord(
                evidence_id=pid,
                evidence_type=EVIDENCE_TYPE_OBJECT_STATE,
                nature=NATURE_OBSERVATION,
            ))
        child = EvidenceRecord(
            evidence_id="EV_CHILD",
            evidence_type=EVIDENCE_TYPE_DIAGNOSTIC,
            nature=NATURE_INFERENCE,
            parent_evidence_ids=["EV_Z", "EV_A", "EV_M"],  # Unsorted
        )
        ledger.add_record(child)

        chain = ledger.trace_provenance_chain("EV_CHILD")
        visited_ids = [step.get("evidence_id") for step in chain if step.get("status") == "RESOLVED"]
        # EV_CHILD visited first, then sorted parents EV_A, EV_M, EV_Z
        self.assertEqual(visited_ids, ["EV_CHILD", "EV_A", "EV_M", "EV_Z"])



if __name__ == "__main__":
    unittest.main()
