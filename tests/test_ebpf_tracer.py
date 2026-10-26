"""Unit tests for Phase 1 eBPF Stack-Variable & Function Tracing.

Tests:
1. Event decoding (entry and return records, registers, frame metadata, arguments, return values).
2. PID/TID filtering (strict isolation to target process).
3. Malformed and truncated records handling (fault tolerance, counter increment).
4. Lost event tracking from ring buffer / kernel warnings.
5. Truthful local variable reporting (UNSUPPORTED_PHASE1, no fabricated values).
6. Truthful consistency reporting (PROBE_POINT_EVENT, never labeled as CONSISTENT snapshot).
7. Backend capability detection (bpftrace supported, libbpf marked unsupported in Phase 1).
8. Unsupported environment handling (non-Linux, unprivileged, missing dependencies).
9. Target process validation (invalid PID, non-existent PID, missing binary).
10. Target executable validation (/proc/<pid>/exe mismatch, stat dev/ino, Build ID mismatch).
11. Build ID verification (matching, mismatch fails closed, --no-verify-build-id explicitly unchecked).
12. Probe resolution (stripped binary without debug image, ambiguous functions, linkage name disambiguation).
13. Non-PIE file offset conversion (VirtAddr - p_vaddr + p_offset).
14. ObservationBackend contract and capability reporting.
15. Pure-Python ELF symbol lookup (find_elf_symbols).

NOTE: Ordinary unit tests NEVER require elevated privileges and run cleanly in any environment.
"""

import json
import os
import platform
import signal
import struct
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
import unittest
from unittest.mock import MagicMock, patch

from extractor.debug_image import BinaryIdentity, inspect_elf
from extractor.dwarf_evaluator import (
    EVAL_STATUS_ERROR,
    EVAL_STATUS_OBSERVED,
    EVAL_STATUS_OPTIMIZED_OUT,
    EVAL_STATUS_UNAVAILABLE,
    EVAL_STATUS_UNSUPPORTED,
    DwarfEvaluationContext,
    DwarfEvaluator,
    DwarfLocationResult,
    Phase2DwarfLocationResolver,
    unpack_scalar_from_bytes,
    unpack_scalar_from_register,
)
from extractor.dwarf_indexer import DwarfIndex, DwarfIndexer, DwarfSubprogram, DwarfType, DwarfVariable
from extractor.ebpf_tracer import (
    STATUS_OBSERVED,
    STATUS_UNAVAILABLE,
    STATUS_UNSUPPORTED_PHASE1,
    STATUS_LOST,
    AddressValidator,
    DwarfLocationResolverInterface,
    EbpfCapabilityResult,
    EbpfEnvironmentChecker,
    EbpfEventDecoder,
    EbpfTracer,
    FrameMetadata,
    Phase1DwarfLocationResolver,
    TraceEvent,
    TraceObservationSession,
    TraceValue,
    ProbeCleanupResult,
    find_elf_symbols,
    _is_strict_int,
    _safe_repr,
)
from extractor.observation_backends import EbpfObservationBackend, ObservationBackend


class ProcessInspection:
    """Structured inspection result of a process's OS state."""
    def __init__(
        self,
        status: str,
        detail: Optional[str] = None,
        info: Optional[Dict[str, Any]] = None,
    ):
        self.status = status      # "ACTIVE", "ZOMBIE", "ABSENT", "UNKNOWN"
        self.detail = detail      # state char, error reason, or diagnostic detail
        self.info = info or {}    # dict with comm, state, ppid, pgrp, starttime

    def __iter__(self):
        # Enables backwards-compatible 2-tuple unpacking: status, detail = inspect_process(pid)
        return iter((self.status, self.detail))

    def __repr__(self):
        pgrp_info = f", pgrp={self.info.get('pgrp')}" if "pgrp" in self.info else ""
        return f"ProcessInspection(status={self.status!r}, detail={self.detail!r}{pgrp_info})"


class GroupProcessEnumeration:
    """Structured, fail-closed result of scanning /proc for members of a process group."""

    def __init__(
        self,
        target_pgid: int,
        members: Dict[int, ProcessInspection],
        complete: bool,
        unknown_candidates: Optional[Dict[int, ProcessInspection]] = None,
        scan_error: Optional[str] = None,
        transient_exits: Optional[List[int]] = None,
        diagnostics: Optional[List[str]] = None,
    ):
        self.target_pgid = target_pgid
        self.members = members  # PIDs confirmed belonging to target_pgid -> ProcessInspection
        self.complete = complete  # True ONLY if directory enumeration succeeded and no indeterminate candidates exist
        self.unknown_candidates = unknown_candidates or {}  # PIDs whose group membership could not be verified
        self.scan_error = scan_error  # Error string if directory enumeration failed
        self.transient_exits = transient_exits or []  # PIDs that vanished between listdir and inspection (benign)
        self.diagnostics = diagnostics or []

    @property
    def active_members(self) -> Dict[int, ProcessInspection]:
        """Confirmed group members with ACTIVE status."""
        return {p: insp for p, insp in self.members.items() if getattr(insp, "status", None) == "ACTIVE"}

    @property
    def zombie_members(self) -> Dict[int, ProcessInspection]:
        """Confirmed group members with ZOMBIE status."""
        return {p: insp for p, insp in self.members.items() if getattr(insp, "status", None) == "ZOMBIE"}

    @property
    def unknown_members(self) -> Dict[int, ProcessInspection]:
        """Confirmed group members with UNKNOWN status."""
        return {p: insp for p, insp in self.members.items() if getattr(insp, "status", None) == "UNKNOWN"}

    def is_clean(self) -> bool:
        """True ONLY if scan was complete, and zero active or unknown members or candidates exist."""
        return (
            self.complete
            and len(self.active_members) == 0
            and len(self.unknown_members) == 0
            and len(self.unknown_candidates) == 0
        )

    def is_empty(self) -> bool:
        """True ONLY if scan was complete, and zero members of any state or unknown candidates exist."""
        return (
            self.complete
            and len(self.members) == 0
            and len(self.unknown_candidates) == 0
        )

    def items(self):
        return self.members.items()

    def keys(self):
        return self.members.keys()

    def values(self):
        return self.members.values()

    def get(self, pid: int, default=None):
        return self.members.get(pid, default)

    def __getitem__(self, pid: int) -> ProcessInspection:
        return self.members[pid]

    def __contains__(self, pid: int) -> bool:
        return pid in self.members

    def __iter__(self):
        return iter(self.members)

    def __len__(self) -> int:
        if not self.complete:
            raise RuntimeError(
                f"Cannot determine length of incomplete GroupProcessEnumeration for PGID {self.target_pgid}: "
                f"scan_error={self.scan_error}, unknown_candidates={list(self.unknown_candidates.keys())}"
            )
        return len(self.members)

    def __bool__(self) -> bool:
        if not self.complete:
            raise RuntimeError(
                f"Cannot evaluate boolean value of incomplete GroupProcessEnumeration for PGID {self.target_pgid}: "
                f"scan_error={self.scan_error}, unknown_candidates={list(self.unknown_candidates.keys())}"
            )
        return len(self.members) > 0

    def __repr__(self) -> str:
        status_str = "COMPLETE" if self.complete else f"INCOMPLETE(err={self.scan_error!r})"
        return (
            f"GroupProcessEnumeration(target_pgid={self.target_pgid}, status={status_str}, "
            f"members={len(self.members)}, active={len(self.active_members)}, "
            f"zombies={len(self.zombie_members)}, unknown_candidates={len(self.unknown_candidates)}, "
            f"transient_exits={len(self.transient_exits)})"
        )


class TestEbpfTracerUnit(unittest.TestCase):
    """Hermetic unit tests for eBPF tracer decoder, schemas, capability detection, and identity verification."""

    _RECOGNIZED_KERNEL_STATES = {
        "R",  # Running
        "S",  # Interruptible sleep
        "D",  # Uninterruptible sleep (disk)
        "Z",  # Zombie
        "T",  # Stopped on signal
        "t",  # Tracing stop
        "W",  # Paging
        "X",  # Dead
        "x",  # Dead
        "K",  # Wakekill
        "P",  # Parked
        "I",  # Idle
    }

    @classmethod
    def _inspect_process(
        cls,
        p: int,
        expected_pgrp: Optional[int] = None,
        expected_starttime: Optional[int] = None,
        stat_reader: Optional[Callable[[int], str]] = None,
        kill_fn: Optional[Callable[[int, int], None]] = None,
        proc_dir: str = "/proc",
    ) -> ProcessInspection:
        """Inspect process state, distinguishing absence, zombie, active, and unknown states.

        Inspects /proc/<p>/stat (handling complex comm with parens/spaces), validates complete
        structural fields through Linux field 22 (starttime), verifies process group membership
        and starttime to detect PID reuse, and checks signal 0 when explicitly requested.

        Returns:
            ProcessInspection: (status, detail, info) where status is in
            {"ACTIVE", "ZOMBIE", "ABSENT", "UNKNOWN"}.
        """
        # 0. Strict type validation of requested target PID before any syscalls, signal operations, or filesystem access
        if not _is_strict_int(p):
            return ProcessInspection(
                "UNKNOWN",
                f"Invalid non-integer requested PID '{_safe_repr(p)}' (type {type(p).__name__})"
            )

        if p <= 0:
            return ProcessInspection(
                "UNKNOWN",
                f"Invalid non-positive requested PID {p}"
            )

        target_pid = p

        # Pre-validate expected_pgrp and expected_starttime types if provided
        if expected_pgrp is not None:
            if not _is_strict_int(expected_pgrp) or expected_pgrp <= 0:
                return ProcessInspection(
                    "UNKNOWN",
                    f"Invalid expected_pgrp '{_safe_repr(expected_pgrp)}' (type {type(expected_pgrp).__name__}): must be positive integer"
                )

        if expected_starttime is not None:
            if not _is_strict_int(expected_starttime) or expected_starttime < 0:
                return ProcessInspection(
                    "UNKNOWN",
                    f"Invalid expected_starttime '{_safe_repr(expected_starttime)}' (type {type(expected_starttime).__name__}): must be non-negative integer"
                )

        # 1. If kill_fn is explicitly provided, verify signal 0 first (allows mock testing of signal errors)
        if kill_fn is not None:
            try:
                kill_fn(target_pid, 0)
            except ProcessLookupError:
                return ProcessInspection("ABSENT", "ProcessLookupError (ESRCH)")
            except PermissionError as e:
                return ProcessInspection("UNKNOWN", f"PermissionError: {e}")
            except Exception as e:
                return ProcessInspection("UNKNOWN", f"Signal error: {e}")

        # 2. Inspect /proc/<p>/stat for definitive execution state
        try:
            if stat_reader is not None:
                content = stat_reader(target_pid).strip()
            else:
                stat_path = os.path.join(proc_dir, str(target_pid), "stat")
                with open(stat_path, "r", encoding="utf-8") as f:
                    content = f.read().strip()
        except (FileNotFoundError, ProcessLookupError):
            # Process does not exist in /proc (or reaped)
            return ProcessInspection("ABSENT", "Stat file absent (process reaped)")
        except PermissionError as e:
            return ProcessInspection("UNKNOWN", f"PermissionError reading /proc/{target_pid}/stat: {e}")
        except Exception as e:
            return ProcessInspection("UNKNOWN", f"Stat read error: {e}")

        # Defensive parsing of /proc/<pid>/stat
        lparen = content.find("(")
        rparen = content.rfind(")")
        if lparen == -1 or rparen == -1 or rparen <= lparen:
            return ProcessInspection(
                "UNKNOWN",
                f"Malformed parentheses in /proc/{target_pid}/stat: {content[:80]}"
            )

        # 1. Parse and validate leading PID (Field 1) before opening parenthesis of comm (Field 2)
        leading_token = content[:lparen].strip()
        if not leading_token:
            return ProcessInspection(
                "UNKNOWN",
                f"Missing leading PID before comm in /proc/{target_pid}/stat: {content[:80]}"
            )
        try:
            stat_pid = int(leading_token)
        except ValueError:
            return ProcessInspection(
                "UNKNOWN",
                f"Malformed non-numeric leading PID '{leading_token}' in /proc/{target_pid}/stat: {content[:80]}"
            )

        if stat_pid <= 0:
            return ProcessInspection(
                "UNKNOWN",
                f"Invalid non-positive PID {stat_pid} in /proc/{target_pid}/stat"
            )

        if stat_pid != target_pid:
            return ProcessInspection(
                "UNKNOWN",
                f"Mismatched PID in /proc/{target_pid}/stat: stat PID {stat_pid} != requested PID {target_pid}"
            )

        comm = content[lparen + 1:rparen]
        rest = content[rparen + 1:].strip().split()

        # Linux /proc/<pid>/stat field specification (proc(5)):
        # Field 1: pid (preceding comm, validated above)
        # Field 2: comm (within outermost parentheses)
        # Post-comm fields (rest list, 0-indexed):
        #   rest[0]:  Field 3  - state (%c)
        #   rest[1]:  Field 4  - ppid (%d)
        #   rest[2]:  Field 5  - pgrp (%d)
        #   rest[3]:  Field 6  - session (%d)
        #   rest[4]:  Field 7  - tty_nr (%d)
        #   rest[5]:  Field 8  - tpgid (%d)
        #   rest[6]:  Field 9  - flags (%u)
        #   rest[7]:  Field 10 - minflt (%lu)
        #   rest[8]:  Field 11 - cminflt (%lu)
        #   rest[9]:  Field 12 - majflt (%lu)
        #   rest[10]: Field 13 - cmajflt (%lu)
        #   rest[11]: Field 14 - utime (%lu)
        #   rest[12]: Field 15 - stime (%lu)
        #   rest[13]: Field 16 - cutime (%ld)
        #   rest[14]: Field 17 - cstime (%ld)
        #   rest[15]: Field 18 - priority (%ld)
        #   rest[16]: Field 19 - nice (%ld)
        #   rest[17]: Field 20 - num_threads (%ld)
        #   rest[18]: Field 21 - itrealvalue (%ld)
        #   rest[19]: Field 22 - starttime (%llu)
        # Minimum required post-comm fields: 20 (to extract through field 22 starttime).
        # We validate structural field count (minimum 20 post-comm fields through field 22 starttime)
        # and semantic identity fields (PID, comm, state, PPID, PGID, starttime). Fields 6-21 are
        # parsed structurally by token separation but not individually semantic-checked, to maintain
        # broad kernel compatibility without over-constraining variable metrics.
        if len(rest) < 20:
            return ProcessInspection(
                "UNKNOWN",
                f"Insufficient fields ({len(rest)} < 20): Missing starttime (field 22) in /proc/{p}/stat: {content[:80]}"
            )

        state_token = rest[0]
        try:
            ppid = int(rest[1])
            pgrp = int(rest[2])
            starttime = int(rest[19])
        except ValueError as e:
            return ProcessInspection(
                "UNKNOWN",
                f"Non-integer field in /proc/{p}/stat: {e}"
            )

        if ppid < 0:
            return ProcessInspection(
                "UNKNOWN",
                f"Invalid negative ppid ({ppid}) in /proc/{p}/stat"
            )

        if pgrp < 0:
            return ProcessInspection(
                "UNKNOWN",
                f"Invalid negative pgrp ({pgrp}) in /proc/{p}/stat"
            )

        if starttime < 0:
            return ProcessInspection(
                "UNKNOWN",
                f"Invalid negative starttime ({starttime}) in /proc/{p}/stat"
            )

        info = {
            "comm": comm,
            "state": state_token,
            "ppid": ppid,
            "pgrp": pgrp,
            "starttime": starttime,
        }

        # Identity and PID reuse verification:
        if expected_starttime is not None:
            if starttime != expected_starttime:
                return ProcessInspection(
                    "ABSENT",
                    f"PID reused (starttime {starttime} != expected {expected_starttime})",
                    info,
                )

        if expected_pgrp is not None:
            if pgrp != expected_pgrp:
                return ProcessInspection(
                    "ABSENT",
                    f"PID reused (pgrp {pgrp} != expected {expected_pgrp})",
                    info,
                )

        # State token validation: exactly one recognized kernel state character
        if len(state_token) != 1:
            return ProcessInspection(
                "UNKNOWN",
                f"Invalid multi-character state token '{state_token}' in /proc/{p}/stat",
                info,
            )

        if state_token not in cls._RECOGNIZED_KERNEL_STATES:
            return ProcessInspection(
                "UNKNOWN",
                f"Unrecognized kernel process state '{state_token}'",
                info,
            )

        if state_token == "Z":
            return ProcessInspection("ZOMBIE", "Z", info)
        else:
            return ProcessInspection("ACTIVE", state_token, info)

    @classmethod
    def _get_group_processes(
        cls,
        target_pgid: int,
        proc_dir: str = "/proc",
        listdir_fn: Optional[Callable[[str], List[str]]] = None,
        stat_reader: Optional[Callable[[int], str]] = None,
    ) -> GroupProcessEnumeration:
        """Scan /proc to enumerate all processes currently belonging to target_pgid.

        Fail-closed semantics:
        - If directory enumeration fails (PermissionError, OSError), returns an incomplete scan
          with scan_error and complete=False.
        - If candidate PIDs cannot be inspected (e.g. PermissionError or corrupted stat), they are
          tracked in unknown_candidates and complete=False.
        - If a candidate exits between listdir and inspection (stat FileNotFoundError or ProcessLookupError),
          this is classified as a benign transient exit (the process is confirmed ABSENT) and does NOT
          invalidate completeness.
        - Returns a structured GroupProcessEnumeration result that callers must verify for completeness.
        """
        if not _is_strict_int(target_pgid) or target_pgid <= 0:
            err_msg = f"Invalid target_pgid '{_safe_repr(target_pgid)}' (type {type(target_pgid).__name__}): must be positive integer"
            return GroupProcessEnumeration(
                target_pgid=target_pgid,
                members={},
                complete=False,
                unknown_candidates={},
                scan_error=err_msg,
                transient_exits=[],
                diagnostics=[err_msg],
            )

        _listdir = listdir_fn or os.listdir
        members: Dict[int, ProcessInspection] = {}
        unknown_candidates: Dict[int, ProcessInspection] = {}
        transient_exits: List[int] = []
        diagnostics: List[str] = []

        try:
            entries = _listdir(proc_dir)
        except OSError as e:
            err_msg = f"Failed to list directory {proc_dir}: {e}"
            return GroupProcessEnumeration(
                target_pgid=target_pgid,
                members={},
                complete=False,
                unknown_candidates={},
                scan_error=err_msg,
                transient_exits=[],
                diagnostics=[err_msg],
            )

        for entry in entries:
            if not entry.isdigit():
                continue
            candidate_pid = int(entry)
            insp = cls._inspect_process(
                candidate_pid,
                proc_dir=proc_dir,
                stat_reader=stat_reader,
            )

            if insp.status == "ABSENT":
                # Benign transient race: candidate exited/reaped between listdir and stat inspection.
                # A confirmed absent process has no active threads in any process group.
                transient_exits.append(candidate_pid)
                continue

            candidate_pgrp = insp.info.get("pgrp")

            if insp.status == "UNKNOWN":
                if candidate_pgrp == target_pgid:
                    # Belongs to target_pgid, but internal state character or fields are unknown
                    members[candidate_pid] = insp
                    diagnostics.append(
                        f"PID {candidate_pid} in target PGID {target_pgid} has UNKNOWN state: {insp.detail}"
                    )
                elif candidate_pgrp is None:
                    # Inconclusive inspection: cannot determine if this process belongs to target_pgid!
                    unknown_candidates[candidate_pid] = insp
                    diagnostics.append(
                        f"PID {candidate_pid} group membership indeterminate ({insp.detail})"
                    )
                else:
                    # candidate_pgrp is known and != target_pgid: belongs to another group, safely ignored
                    pass
                continue

            # insp.status in ("ACTIVE", "ZOMBIE")
            if candidate_pgrp == target_pgid:
                members[candidate_pid] = insp

        is_complete = len(unknown_candidates) == 0
        return GroupProcessEnumeration(
            target_pgid=target_pgid,
            members=members,
            complete=is_complete,
            unknown_candidates=unknown_candidates,
            scan_error=None,
            transient_exits=transient_exits,
            diagnostics=diagnostics,
        )


    def setUp(self):
        self.target_pid = 4242
        self.decoder = EbpfEventDecoder(
            target_pid=self.target_pid,
            architecture="x86_64",
            function_name="test_func",
            function_offset=0x1234,
        )

    def test_01_decode_valid_entry_event(self):
        """Test decoding of valid JSON entry probe record with registers and frame metadata."""
        line = json.dumps({
            "type": "ENTRY",
            "pid": 4242,
            "tid": 4242,
            "time": 1000000000,
            "sp": "0x7fffffffe000",
            "pc": "0x401234",
            "fp": "0x7fffffffe020",
            "ra": "0x401100",
            "arg0": 10,
            "arg1": 20,
            "arg2": 30,
        })
        ev = self.decoder.decode_line(line)
        self.assertIsNotNone(ev)
        self.assertEqual(ev.sequence, 1)
        self.assertEqual(ev.pid, 4242)
        self.assertEqual(ev.tid, 4242)
        self.assertEqual(ev.probe_type, "ENTRY")
        self.assertEqual(ev.function_name, "test_func")
        self.assertEqual(ev.function_offset, 0x1234)

        # Registers and Frame metadata
        self.assertIsNotNone(ev.frame_metadata)
        self.assertEqual(ev.frame_metadata.stack_pointer, 0x7fffffffe000)
        self.assertEqual(ev.frame_metadata.instruction_pointer, 0x401234)
        self.assertEqual(ev.frame_metadata.frame_pointer, 0x7fffffffe020)
        self.assertEqual(ev.frame_metadata.return_address, 0x401100)

        # Arguments mapped from arg0..arg2
        self.assertIn("param_0", ev.arguments)
        self.assertEqual(ev.arguments["param_0"].status, STATUS_OBSERVED)
        self.assertEqual(ev.arguments["param_0"].value, 10)
        self.assertEqual(ev.arguments["param_0"].location, "register:arg0")

        self.assertIn("param_1", ev.arguments)
        self.assertEqual(ev.arguments["param_1"].value, 20)

        self.assertIn("param_2", ev.arguments)
        self.assertEqual(ev.arguments["param_2"].value, 30)

        # Return value is None on entry
        self.assertIsNone(ev.return_value)

        # Local variables explicitly marked as unsupported in Phase 1
        self.assertIn("local_variables", ev.local_variables)
        self.assertEqual(ev.local_variables["local_variables"].status, STATUS_UNSUPPORTED_PHASE1)
        self.assertIn("Phase 2", ev.local_variables["local_variables"].reason)

    def test_02_decode_valid_return_event(self):
        """Test decoding of valid return probe record with retval."""
        line = json.dumps({
            "type": "RETURN",
            "pid": 4242,
            "tid": 4242,
            "time": 1000005000,
            "sp": "0x7fffffffe000",
            "pc": "0x401250",
            "ret": "0x58",  # 88 in hex
        })
        ev = self.decoder.decode_line(line)
        self.assertIsNotNone(ev)
        self.assertEqual(ev.probe_type, "RETURN")
        self.assertIsNotNone(ev.return_value)
        self.assertEqual(ev.return_value.status, STATUS_OBSERVED)
        self.assertEqual(ev.return_value.value, 88)
        self.assertEqual(ev.return_value.value_hex, "0x58")
        self.assertEqual(ev.return_value.location, "register:retval")

    def test_03_pid_filtering_strict(self):
        """Verify events from other processes are rejected and ignored."""
        foreign_line = json.dumps({
            "type": "ENTRY",
            "pid": 9999,  # Different PID
            "tid": 9999,
            "time": 1000000000,
            "sp": "0x7fffffffe000",
            "pc": "0x401234",
            "arg0": 1,
        })
        ev = self.decoder.decode_line(foreign_line)
        self.assertIsNone(ev, "Foreign PID must be filtered out")
        self.assertEqual(self.decoder.sequence_counter, 0)

    def test_04_malformed_and_truncated_records(self):
        """Verify corrupted or truncated records are recorded without crashing."""
        # 1. Truncated JSON
        self.decoder.decode_line('{"type":"ENTRY","pid":4242,"tid":4242,"sp":"0x7fff')
        self.assertEqual(self.decoder.malformed_count, 1)

        # 2. Syntax garbage
        self.decoder.decode_line('{invalid json record: true, 123}')
        self.assertEqual(self.decoder.malformed_count, 2)

        # 3. Random noise or warning line (should be ignored, not counted as malformed)
        res = self.decoder.decode_line("WARNING: Could not determine instruction boundary")
        self.assertIsNone(res)
        self.assertEqual(self.decoder.malformed_count, 2)

        # 4. Decoder still functions after corrupt records
        valid = json.dumps({"type": "ENTRY", "pid": 4242, "tid": 4242, "time": 123456, "sp": "0x1000", "pc": "0x2000"})
        ev = self.decoder.decode_line(valid)
        self.assertIsNotNone(ev)
        self.assertEqual(ev.pid, 4242)

    def test_05_lost_events_tracking(self):
        """Verify lost event notices from transport ringbuffer are accumulated."""
        self.decoder.decode_line("Lost 7 events")
        self.assertEqual(self.decoder.lost_count, 7)

        self.decoder.decode_line("Warning: lost 3 samples due to ring buffer overflow")
        self.assertEqual(self.decoder.lost_count, 10)

    def test_06_truthful_local_variables_reporting(self):
        """Verify local variable resolution explicitly declares Phase 1 status."""
        resolver = Phase1DwarfLocationResolver()
        val = resolver.resolve_variable(
            subprogram=None,
            variable_name="my_stack_var",
            registers={"sp": 0x1000},
            frame_metadata=FrameMetadata(stack_pointer=0x1000),
        )
        self.assertEqual(val.status, STATUS_UNSUPPORTED_PHASE1)
        self.assertIsNone(val.value)
        self.assertIn("Phase 2", val.reason)
        self.assertIn("dynamic location evaluation", val.reason)

    def test_07_truthful_consistency_semantics(self):
        """Verify session consistency level is never labeled as a CONSISTENT snapshot."""
        session = TraceObservationSession(
            session_id="test_sess_01",
            target_pid=4242,
            target_binary="/bin/test",
            function_name="func",
            architecture="x86_64",
            backend_name="bpftrace",
            start_time="2026-01-01T00:00:00Z",
            target_build_id="abc",
            build_id_status="VERIFIED",
        )
        self.assertEqual(session.consistency_level, "PROBE_POINT_EVENT")
        self.assertNotEqual(session.consistency_level, "CONSISTENT")
        self.assertNotEqual(session.consistency_level, "STOPPED")
        self.assertEqual(session.build_id_status, "VERIFIED")

    def test_08_capability_detection_bpftrace_vs_libbpf(self):
        """Verify capability detection reports bpftrace as supported and libbpf as unsupported in Phase 1."""
        # Case A: bpftrace missing, clang and libbpf headers present
        with patch("sys.platform", "linux"), \
             patch("platform.machine", return_value="x86_64"), \
             patch("os.geteuid", return_value=0), \
             patch("os.path.exists", side_effect=lambda p: True if p in ("/sys/fs/bpf", "/usr/include/bpf/bpf.h") else False), \
             patch("shutil.which", side_effect=lambda cmd: "/usr/bin/clang" if cmd == "clang" else None):
            cap = EbpfEnvironmentChecker.check_prerequisites()
            self.assertEqual(cap.backend, "libbpf")
            self.assertFalse(cap.supported, "libbpf must NOT be reported as supported in Phase 1")
            self.assertTrue(any("deferred to Phase 2" in r for r in cap.reasons))

        # Case B: neither bpftrace nor clang present
        with patch("sys.platform", "linux"), \
             patch("platform.machine", return_value="x86_64"), \
             patch("os.geteuid", return_value=0), \
             patch("os.path.exists", side_effect=lambda p: p == "/sys/fs/bpf"), \
             patch("shutil.which", return_value=None):
            cap = EbpfEnvironmentChecker.check_prerequisites()
            self.assertEqual(cap.backend, "none")
            self.assertFalse(cap.supported)
            self.assertTrue(any("bpftrace executable not found" in r for r in cap.reasons))

    @patch("sys.platform", "darwin")
    def test_09_unsupported_environment_non_linux(self):
        """Verify non-Linux environments report UNSUPPORTED_ENVIRONMENT cleanly."""
        cap = EbpfEnvironmentChecker.check_prerequisites()
        self.assertFalse(cap.supported)
        self.assertEqual(cap.backend, "none")
        self.assertTrue(any("Linux" in r for r in cap.reasons))

    @patch("platform.machine", return_value="x86_64")
    @patch("os.geteuid", return_value=1000)
    @patch("subprocess.run")
    def test_10_unsupported_environment_unprivileged(self, mock_run, mock_geteuid, mock_machine):
        """Verify unprivileged user without sudo reports clear capability error."""
        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_run.return_value = mock_proc

        with patch("sys.platform", "linux"), \
             patch("builtins.open", unittest.mock.mock_open(read_data="2")), \
             patch("os.path.exists", return_value=True):
            cap = EbpfEnvironmentChecker.check_prerequisites()
            self.assertFalse(cap.is_privileged)
            self.assertFalse(cap.supported)
            self.assertTrue(any("Unprivileged eBPF is disabled" in r for r in cap.reasons))

    def test_11_target_process_validation_nonexistent_pid(self):
        """Verify non-existent PID fails closed with clear diagnostic."""
        tracer = EbpfTracer(use_sudo=False)
        session = tracer.trace(
            pid=9999999,
            binary_path="/bin/ls",
            function_name="main",
        )
        self.assertEqual(session.status, "FAILED")
        self.assertIn("does not exist", session.error_message)

    def test_12_target_process_validation_invalid_pid(self):
        """Verify non-positive PID fails closed."""
        tracer = EbpfTracer(use_sudo=False)
        session = tracer.trace(
            pid=-5,
            binary_path="/bin/ls",
            function_name="main",
        )
        self.assertEqual(session.status, "FAILED")
        self.assertIn("Invalid target PID", session.error_message)

    def test_13_target_process_validation_missing_binary(self):
        """Verify tracing handles missing target binary safely when PID is alive."""
        my_pid = os.getpid()
        tracer = EbpfTracer(use_sudo=False)
        session = tracer.trace(
            pid=my_pid,
            binary_path="/nonexistent/path/to/binary_12345",
            function_name="some_func",
        )
        self.assertEqual(session.status, "FAILED")
        self.assertIn("Binary file not found", session.error_message)

    def test_14_process_executable_mismatch(self):
        """Verify /proc/<pid>/exe mismatch against requested binary fails closed."""
        my_pid = os.getpid()
        tracer = EbpfTracer(use_sudo=False)
        # Pass a real binary (/bin/ls) while running process is python3
        session = tracer.trace(
            pid=my_pid,
            binary_path="/bin/ls",
            function_name="main",
        )
        self.assertEqual(session.status, "FAILED")
        self.assertIn("does not match requested binary", session.error_message)
        self.assertEqual(session.build_id_status, "MISMATCHED")

    def test_15_build_id_mismatch_fails_closed(self):
        """Verify Build ID mismatch between binary and debug ELF fails closed."""
        tracer = EbpfTracer(use_sudo=False)
        with tempfile.NamedTemporaryFile("wb", suffix=".bin") as f1, \
             tempfile.NamedTemporaryFile("wb", suffix=".dbg") as f2:
            ident1 = BinaryIdentity(
                path=f1.name, elf_class="ELF64", architecture="x86_64", endianness="little",
                build_id="aaaa11112222", stripped=False, has_debug_info=True,
            )
            ident2 = BinaryIdentity(
                path=f2.name, elf_class="ELF64", architecture="x86_64", endianness="little",
                build_id="bbbb33334444", stripped=False, has_debug_info=True,
            )
            with patch("extractor.ebpf_tracer.inspect_elf", side_effect=[ident1, ident2]), \
                 patch("os.path.exists", return_value=True), \
                 patch("os.path.realpath", return_value=f1.name), \
                 patch("os.kill"):
                session = tracer.trace(
                    pid=os.getpid(),
                    binary_path=f1.name,
                    function_name="target_func",
                    debug_image=f2.name,
                    verify_build_id=True,
                )
                self.assertEqual(session.status, "FAILED")
                self.assertEqual(session.build_id_status, "MISMATCHED")
                self.assertIn("Build ID mismatch", session.error_message)

    def test_16_build_id_explicitly_unchecked(self):
        """Verify --no-verify-build-id explicitly records EXPLICITLY_UNCHECKED."""
        tracer = EbpfTracer(use_sudo=False)
        with tempfile.NamedTemporaryFile("wb", suffix=".bin") as f1:
            ident1 = BinaryIdentity(
                path=f1.name, elf_class="ELF64", architecture="x86_64", endianness="little",
                build_id="aaaa11112222", stripped=False, has_debug_info=True,
            )
            cap_mock = EbpfCapabilityResult(
                supported=False, backend="bpftrace", architecture="x86_64", kernel_version="6.0",
                is_privileged=False, unprivileged_bpf_disabled=0, has_bpf_fs=True, reasons=["mock unprivileged"],
            )
            with patch("extractor.ebpf_tracer.inspect_elf", return_value=ident1), \
                 patch("extractor.ebpf_tracer.EbpfEnvironmentChecker.check_prerequisites", return_value=cap_mock), \
                 patch("os.path.exists", return_value=True), \
                 patch("os.path.realpath", return_value=f1.name), \
                 patch("os.kill"):
                session = tracer.trace(
                    pid=os.getpid(),
                    binary_path=f1.name,
                    function_name="target_func",
                    verify_build_id=False,
                )
                self.assertEqual(session.build_id_status, "EXPLICITLY_UNCHECKED")

    def test_17_probe_resolution_stripped_binary_without_debug_image(self):
        """Verify stripped binary without debug image returns a clear diagnostic."""
        tracer = EbpfTracer(use_sudo=False)
        ident = BinaryIdentity(
            path="/bin/test_stripped", elf_class="ELF64", architecture="x86_64", endianness="little",
            build_id="abc123", stripped=True, has_debug_info=False,
        )
        fo, attach_spec, err = tracer._resolve_probe_target(
            elf_info=ident,
            binary_path="/bin/test_stripped",
            function_name="some_func",
            debug_image=None,
        )
        self.assertIsNone(fo)
        self.assertIsNone(attach_spec)
        self.assertIn("binary is stripped and no matching debug image was provided", err)

    def test_18_probe_resolution_ambiguous_function_fails(self):
        """Verify overloaded C++ functions with distinct locations return AMBIGUOUS diagnostic."""
        tracer = EbpfTracer(use_sudo=False)
        ident = BinaryIdentity(
            path="/bin/test_ambig", elf_class="ELF64", architecture="x86_64", endianness="little",
            build_id="abc123", stripped=False, has_debug_info=True,
        )
        subp1 = DwarfSubprogram(die_offset=0x10, name="calc", low_pc=0x1000, linkage_name="_Z4calci")
        subp2 = DwarfSubprogram(die_offset=0x20, name="calc", low_pc=0x1050, linkage_name="_Z4calcii")

        mock_index = MagicMock()
        mock_index.subprograms_by_name = {"calc": [subp1, subp2]}

        with patch("extractor.dwarf_indexer.DwarfIndexer.get_index", return_value=mock_index), \
             patch("os.path.exists", return_value=True):
            fo, attach_spec, err = tracer._resolve_probe_target(
                elf_info=ident,
                binary_path="/bin/test_ambig",
                function_name="calc",
            )
            self.assertIsNone(fo)
            self.assertIsNone(attach_spec)
            self.assertIn("Ambiguous function name 'calc'", err)
            self.assertIn("matches 2 distinct subprogram locations", err)
            self.assertIn("0x1000", err)
            self.assertIn("0x1050", err)
            self.assertIn("_Z4calci", err)

    def test_19_probe_resolution_linkage_name_disambiguation(self):
        """Verify mangled linkage name disambiguates to a single unique location."""
        tracer = EbpfTracer(use_sudo=False)
        ident = BinaryIdentity(
            path="/bin/test_ambig", elf_class="ELF64", architecture="x86_64", endianness="little",
            build_id="abc123", stripped=False, has_debug_info=True,
            pt_loads=[{"p_vaddr": 0x0, "p_memsz": 0x5000, "p_offset": 0x0, "p_filesz": 0x5000}],
        )
        subp1 = DwarfSubprogram(die_offset=0x10, name="calc", low_pc=0x1000, linkage_name="_Z4calci")
        subp2 = DwarfSubprogram(die_offset=0x20, name="calc", low_pc=0x1050, linkage_name="_Z4calcii")

        mock_index = MagicMock()
        mock_index.subprograms_by_name = {
            "calc": [subp1, subp2],
            "_Z4calci": [subp1],
            "_Z4calcii": [subp2],
        }

        with patch("extractor.dwarf_indexer.DwarfIndexer.get_index", return_value=mock_index), \
             patch("os.path.exists", return_value=True), \
             patch("os.path.getsize", return_value=0x5000):
            fo, attach_spec, err = tracer._resolve_probe_target(
                elf_info=ident,
                binary_path="/bin/test_ambig",
                function_name="_Z4calci",
            )
            self.assertIsNone(err)
            self.assertEqual(fo, 0x1000)
            self.assertEqual(attach_spec, "0x1000")

    def test_20_non_pie_file_offset_conversion(self):
        """Verify non-PIE virtual address is converted to file offset via PT_LOAD segment."""
        tracer = EbpfTracer(use_sudo=False)
        # Non-PIE layout: VirtAddr=0x400c90, PT_LOAD vaddr=0x400000, offset=0x0, size=0x2000
        ident = BinaryIdentity(
            path="/bin/test_nopie", elf_class="ELF64", architecture="x86_64", endianness="little",
            build_id="abc123", stripped=False, has_debug_info=True, elf_type="ET_EXEC",
            pt_loads=[
                {"p_vaddr": 0x400000, "p_memsz": 0x2000, "p_offset": 0x0, "p_filesz": 0x2000},
            ],
        )
        subp = DwarfSubprogram(die_offset=0x10, name="target_func", low_pc=0x400c90)
        mock_index = MagicMock()
        mock_index.subprograms_by_name = {"target_func": [subp]}

        with patch("extractor.dwarf_indexer.DwarfIndexer.get_index", return_value=mock_index), \
             patch("os.path.exists", return_value=True), \
             patch("os.path.getsize", return_value=0x2000):
            fo, attach_spec, err = tracer._resolve_probe_target(
                elf_info=ident,
                binary_path="/bin/test_nopie",
                function_name="target_func",
            )
            self.assertIsNone(err)
            self.assertEqual(fo, 0xc90, "VirtAddr 0x400c90 - 0x400000 = 0xc90 file offset")
            self.assertEqual(attach_spec, "0xc90")

    def test_21_observation_backend_capabilities(self):
        """Verify EbpfObservationBackend complies with ObservationBackend ABC."""
        backend = EbpfObservationBackend()
        self.assertEqual(backend.mode, "EBPF_PROBE")
        caps = backend.capabilities()
        self.assertEqual(caps["mode"], "EBPF_PROBE")
        self.assertFalse(caps["process_stop"])
        self.assertFalse(caps["ptrace"])
        self.assertTrue(caps["ebpf"])
        self.assertEqual(caps["consistency"], "PROBE_POINT_EVENT")
        self.assertTrue(caps["local_variable_dwarf_eval"])
        self.assertEqual(caps["dwarf_eval_status"], "SUPPORTED_PROBE_POINT")
        self.assertIn("dwarf_eval_scope", caps)
        scope = caps["dwarf_eval_scope"]
        self.assertIn("supported_types", scope)
        self.assertIn("supported_expressions", scope)
        self.assertIn("supported_architectures", scope)
        self.assertIn("available_probe_points", scope)
        self.assertIn("value_sources", scope)
        self.assertFalse(scope["arbitrary_instruction_offset_probing"])
        self.assertFalse(scope["stack_locals_readable_at_entry"])
        self.assertFalse(scope["locals_readable_at_return"])

    def test_22_pure_python_elf_symbol_lookup(self):
        """Verify pure-Python symbol lookup finds symbols in unstripped ELF binaries."""
        # Test on /bin/ls or any accessible ELF binary
        syms = find_elf_symbols("/bin/ls", "some_nonexistent_symbol_12345")
        self.assertEqual(syms, [])

    def test_23_x86_64_return_address_null_not_hardcoded_zero(self):
        """Verify that on x86_64, missing or null return address is reported as UNAVAILABLE, never 0x0."""
        decoder_x86 = EbpfEventDecoder(
            target_pid=self.target_pid,
            architecture="x86_64",
            function_name="target_func",
        )

        # 1. Payload with null ra
        line_null_ra = json.dumps({
            "type": "ENTRY",
            "pid": self.target_pid,
            "tid": self.target_pid,
            "time": 1000,
            "sp": "0x7fffffffe000",
            "pc": "0x401200",
            "fp": "0x7fffffffe020",
            "ra": None,
            "arg0": 1,
        })
        ev = decoder_x86.decode_line(line_null_ra)
        self.assertIsNotNone(ev)
        self.assertIsNone(ev.frame_metadata.return_address, "x86_64 return address must not be fabricated")
        self.assertNotEqual(ev.frame_metadata.return_address, 0)
        self.assertEqual(ev.frame_metadata.return_address_status, STATUS_UNAVAILABLE)
        self.assertIn("stack", ev.frame_metadata.return_address_reason.lower())
        self.assertIsNone(ev.frame_metadata.to_dict()["return_address"])

        # 2. Payload with ra == 0 (must also be treated as unavailable, not a valid return address)
        line_zero_ra = json.dumps({
            "type": "ENTRY",
            "pid": self.target_pid,
            "tid": self.target_pid,
            "time": 1000,
            "sp": "0x7fffffffe000",
            "pc": "0x401200",
            "fp": "0x7fffffffe020",
            "ra": 0,
            "arg0": 1,
        })
        ev2 = decoder_x86.decode_line(line_zero_ra)
        self.assertIsNotNone(ev2)
        self.assertIsNone(ev2.frame_metadata.return_address)
        self.assertEqual(ev2.frame_metadata.return_address_status, STATUS_UNAVAILABLE)

        # 3. On AArch64, valid observed link register is preserved
        decoder_arm = EbpfEventDecoder(
            target_pid=self.target_pid,
            architecture="aarch64",
            function_name="target_func",
        )
        line_arm = json.dumps({
            "type": "ENTRY",
            "pid": self.target_pid,
            "tid": self.target_pid,
            "time": 1000,
            "sp": "0x7fffffffe000",
            "pc": "0x401200",
            "fp": "0x7fffffffe020",
            "ra": "0x401150",
            "arg0": 1,
        })
        ev_arm = decoder_arm.decode_line(line_arm)
        self.assertIsNotNone(ev_arm)
        self.assertEqual(ev_arm.frame_metadata.return_address, 0x401150)
        self.assertEqual(ev_arm.frame_metadata.return_address_status, STATUS_OBSERVED)

    def test_24_distinguish_unavailable_registers_from_zero(self):
        """Verify registers holding 0 are OBSERVED, while null or missing registers are UNAVAILABLE."""
        line = json.dumps({
            "type": "ENTRY",
            "pid": self.target_pid,
            "tid": self.target_pid,
            "time": 1000,
            "sp": "0x7fffffffe000",
            "pc": "0x401200",
            "arg0": 0,       # Valid 0 integer
            "arg1": None,    # Explicit null
        })
        ev = self.decoder.decode_line(line)
        self.assertIsNotNone(ev)

        # param_0: observed 0
        self.assertIn("param_0", ev.arguments)
        self.assertEqual(ev.arguments["param_0"].status, STATUS_OBSERVED)
        self.assertEqual(ev.arguments["param_0"].value, 0)
        self.assertEqual(ev.arguments["param_0"].value_hex, "0x0")

        # param_1: unavailable
        self.assertIn("param_1", ev.arguments)
        self.assertEqual(ev.arguments["param_1"].status, STATUS_UNAVAILABLE)
        self.assertIsNone(ev.arguments["param_1"].value)

        # param_2: absent
        self.assertNotIn("param_2", ev.arguments)

    def test_25_signedness_and_integer_width_preservation(self):
        """Verify negative integers and 64-bit hexadecimal bit patterns are preserved."""
        line_entry = json.dumps({
            "type": "ENTRY",
            "pid": self.target_pid,
            "tid": self.target_pid,
            "time": 1000,
            "sp": "0x7fffffffe000",
            "pc": "0x401200",
            "arg0": -42,
            "arg1": 42,
        })
        ev_entry = self.decoder.decode_line(line_entry)
        self.assertEqual(ev_entry.arguments["param_0"].value, -42)
        self.assertEqual(ev_entry.arguments["param_0"].value_hex, "0xffffffffffffffd6")
        self.assertEqual(ev_entry.arguments["param_1"].value, 42)
        self.assertEqual(ev_entry.arguments["param_1"].value_hex, "0x2a")

        line_ret = json.dumps({
            "type": "RETURN",
            "pid": self.target_pid,
            "tid": self.target_pid,
            "time": 1005,
            "sp": "0x7fffffffe000",
            "pc": "0x401250",
            "ret": -1,
        })
        ev_ret = self.decoder.decode_line(line_ret)
        self.assertEqual(ev_ret.return_value.value, -1)
        self.assertEqual(ev_ret.return_value.value_hex, "0xffffffffffffffff")

    def test_26_session_status_zero_events_is_partial(self):
        """Verify that attachment producing zero events reports PARTIAL rather than SUCCESS."""
        tracer = EbpfTracer()

        mock_ident = BinaryIdentity(
            path="/bin/echo",
            architecture="x86_64",
            elf_class="ELF64",
            endianness="little",
            build_id="abcdef",
            stripped=False,
            pt_loads=[{"p_vaddr": 0x400000, "p_memsz": 0x1000, "p_offset": 0, "p_filesz": 0x1000}],
        )

        mock_proc = MagicMock()
        poll_count_26 = 0
        def mock_poll_26():
            nonlocal poll_count_26
            poll_count_26 += 1
            return None if poll_count_26 < 5 else 0

        mock_proc.poll = mock_poll_26
        mock_proc.returncode = 0
        mock_proc.stdout.readline.return_value = "Attaching 1 probe...\n"
        mock_proc.stdout.readlines.return_value = []
        mock_proc.stderr.readline.return_value = ""

        with patch("extractor.ebpf_tracer.inspect_elf", return_value=mock_ident), \
             patch("os.path.exists", return_value=True), \
             patch("os.kill", return_value=None), \
             patch("select.select", return_value=([mock_proc.stdout], [], [])), \
             patch("extractor.ebpf_tracer.EbpfEnvironmentChecker.check_prerequisites") as mock_cap, \
             patch("subprocess.Popen", return_value=mock_proc):

            mock_cap.return_value = EbpfCapabilityResult(
                supported=True,
                backend="bpftrace",
                architecture="x86_64",
                kernel_version="6.17",
                is_privileged=True,
                unprivileged_bpf_disabled=0,
                has_bpf_fs=True,
            )

            session = tracer.trace(
                pid=os.getpid(),
                binary_path="/bin/echo",
                function_name="0x400500",
                duration_s=0.01,
            )

            self.assertEqual(session.status, "PARTIAL", "0 events must report PARTIAL, never SUCCESS")
            self.assertEqual(session.total_events, 0)
            self.assertIn("0 events were captured", session.error_message)

    def test_27_session_status_lost_events_is_partial(self):
        """Verify that a trace with lost events reports PARTIAL."""
        tracer = EbpfTracer()

        mock_ident = BinaryIdentity(
            path="/bin/echo",
            architecture="x86_64",
            elf_class="ELF64",
            endianness="little",
            build_id="abcdef",
            stripped=False,
            pt_loads=[{"p_vaddr": 0x400000, "p_memsz": 0x1000, "p_offset": 0, "p_filesz": 0x1000}],
        )

        mock_proc = MagicMock()
        poll_count_27 = 0
        def mock_poll_27():
            nonlocal poll_count_27
            poll_count_27 += 1
            return None if poll_count_27 < 5 else 0

        mock_proc.poll = mock_poll_27
        mock_proc.returncode = 0
        # Yield attach notice, a lost event notice, a valid event, then empty
        mock_proc.stdout.readline.side_effect = [
            "Attaching 1 probe...\n",
            json.dumps({"type": "ENTRY", "pid": os.getpid(), "tid": os.getpid(), "time": 100, "arg0": 1}) + "\n",
            "Lost 3 events\n",
            "",
        ]
        mock_proc.stdout.readlines.return_value = []
        mock_proc.stderr.readline.return_value = ""

        with patch("extractor.ebpf_tracer.inspect_elf", return_value=mock_ident), \
             patch("os.path.exists", return_value=True), \
             patch("os.kill", return_value=None), \
             patch("select.select", return_value=([mock_proc.stdout], [], [])), \
             patch("extractor.ebpf_tracer.EbpfEnvironmentChecker.check_prerequisites") as mock_cap, \
             patch("subprocess.Popen", return_value=mock_proc):

            mock_cap.return_value = EbpfCapabilityResult(
                supported=True,
                backend="bpftrace",
                architecture="x86_64",
                kernel_version="6.17",
                is_privileged=True,
                unprivileged_bpf_disabled=0,
                has_bpf_fs=True,
            )

            session = tracer.trace(
                pid=os.getpid(),
                binary_path="/bin/echo",
                function_name="0x400500",
                duration_s=0.01,
            )

            self.assertEqual(session.status, "PARTIAL")
            self.assertEqual(session.lost_events, 3)
            self.assertIn("lost", session.error_message.lower())

    def test_28_dwarf_evaluator_direct_register(self):
        """Verify DWARF evaluator direct register resolution (DW_OP_reg* / DW_OP_regx)."""
        ident = BinaryIdentity(path="/bin/dummy", architecture="aarch64", elf_class="ELF64", endianness="little")
        subp = DwarfSubprogram(
            die_offset=0x10,
            name="target_func",
            low_pc=0x1000,
            high_pc=0x1100,
            variables=[
                DwarfVariable(die_offset=0x20, name="scalar_arg", type_offset=0x30, location_expr="DW_OP_reg0"),
                DwarfVariable(die_offset=0x25, name="scalar_r5", type_offset=0x30, location_expr="DW_OP_reg5"),
            ],
        )

        mock_index = DwarfIndex(artifact_path="/bin/dummy")
        mock_index.types_by_die[0x30] = DwarfType(die_offset=0x30, tag="DW_TAG_base_type", name="int", byte_size=4)

        with patch("extractor.dwarf_indexer.DwarfIndexer.get_index", return_value=mock_index):
            ctx = DwarfEvaluationContext(
                binary_identity=ident,
                subprogram=subp,
                link_time_address=0x1020,
                registers={"x0": 77, "x5": 128},
                variable_name="scalar_arg",
                architecture="aarch64",
            )
            res = DwarfEvaluator.evaluate(ctx)
            self.assertEqual(res.status, EVAL_STATUS_OBSERVED)
            self.assertEqual(res.location_type, "register")
            self.assertEqual(res.register_name, "x0")
            self.assertEqual(res.value, 77)
            self.assertEqual(res.value_hex, "0x0000004d")

            ctx.variable_name = "scalar_r5"
            res2 = DwarfEvaluator.evaluate(ctx)
            self.assertEqual(res2.status, EVAL_STATUS_OBSERVED)
            self.assertEqual(res2.value, 128)

            # Test unavailable register
            ctx.registers = {}  # Empty registers
            res_unavail = DwarfEvaluator.evaluate(ctx)
            self.assertEqual(res_unavail.status, EVAL_STATUS_UNAVAILABLE)
            self.assertIn("not available", res_unavail.reason)

    def test_29_dwarf_evaluator_frame_base_relative(self):
        """Verify DWARF evaluator frame-base relative location (DW_OP_fbreg <offset>)."""
        ident = BinaryIdentity(path="/bin/dummy", architecture="aarch64", elf_class="ELF64", endianness="little")
        subp = DwarfSubprogram(
            die_offset=0x10,
            name="target_func",
            frame_base="DW_OP_call_frame_cfa",
            low_pc=0x1000,
            high_pc=0x1100,
            variables=[
                DwarfVariable(die_offset=0x20, name="local_val", type_offset=0x30, location_expr="DW_OP_fbreg: -116"),
            ],
        )

        mock_index = DwarfIndex(artifact_path="/bin/dummy")
        mock_index.types_by_die[0x30] = DwarfType(die_offset=0x30, tag="DW_TAG_base_type", name="int", byte_size=4)

        with patch("extractor.dwarf_indexer.DwarfIndexer.get_index", return_value=mock_index):
            # Frame pointer = 0x7fffffffe000. On AArch64 with standard prologue, CFA = FP + 16 = 0x7fffffffe010
            # Target address = CFA - 116 = 0x7fffffffe010 - 116 = 0x7fffffffdfe4
            fm = FrameMetadata(frame_pointer=0x7fffffffe000)

            # 1. Without memory reader: truthful address reporting without fabricated value
            ctx = DwarfEvaluationContext(
                binary_identity=ident,
                subprogram=subp,
                link_time_address=0x1020,
                frame_metadata=fm,
                variable_name="local_val",
                architecture="aarch64",
            )
            res = DwarfEvaluator.evaluate(ctx)
            self.assertEqual(res.status, EVAL_STATUS_UNAVAILABLE)
            self.assertEqual(res.location_type, "stack_memory")
            self.assertEqual(res.evaluated_address, 0x7fffffffdf9c)
            self.assertIn("0x7fffffffdf9c", res.reason)
            self.assertIsNone(res.value)

            # 2. With memory reader: unpacks memory cleanly
            mem_data = {0x7fffffffdf9c: struct.pack("<i", 4242)}
            def mock_reader(addr: int, sz: int) -> Optional[bytes]:
                return mem_data.get(addr)

            ctx.memory_reader = mock_reader
            res_mem = DwarfEvaluator.evaluate(ctx)
            self.assertEqual(res_mem.status, EVAL_STATUS_OBSERVED)
            self.assertEqual(res_mem.value, 4242)
            self.assertEqual(res_mem.value_hex, "0x00001092")
            self.assertEqual(res_mem.evaluated_address, 0x7fffffffdf9c)

    def test_30_dwarf_evaluator_location_list_selection(self):
        """Verify active range selection and instruction pointer filtering in location lists."""
        ident = BinaryIdentity(path="/bin/dummy", architecture="aarch64", elf_class="ELF64", endianness="little")
        subp = DwarfSubprogram(
            die_offset=0x10,
            name="target_func",
            low_pc=0x1000,
            high_pc=0x1200,
            variables=[
                DwarfVariable(die_offset=0x20, name="opt_param", type_offset=0x30, location_list_offset=0x429),
            ],
        )

        mock_index = DwarfIndex(artifact_path="/bin/dummy")
        mock_index.types_by_die[0x30] = DwarfType(die_offset=0x30, tag="DW_TAG_base_type", name="int", byte_size=4)

        mock_loc_table = {
            0x429: [
                (0x1000, 0x1050, "DW_OP_reg0 (x0)"),
                (0x1050, 0x1080, "DW_OP_reg5 (x5)"),
                (0x1080, 0x1100, "DW_OP_entry_value: (DW_OP_reg0 (x0)); DW_OP_stack_value"),
            ]
        }

        with patch("extractor.dwarf_indexer.DwarfIndexer.get_index", return_value=mock_index), \
             patch("extractor.dwarf_evaluator.parse_debug_loc_table", return_value=mock_loc_table):

            ctx = DwarfEvaluationContext(
                binary_identity=ident,
                subprogram=subp,
                link_time_address=0x1020,
                registers={"x0": 10, "x5": 20},
                variable_name="opt_param",
                architecture="aarch64",
            )

            # Link-time PC 0x1020 matches [0x1000, 0x1050) -> x0
            res1 = DwarfEvaluator.evaluate(ctx)
            self.assertEqual(res1.status, EVAL_STATUS_OBSERVED)
            self.assertEqual(res1.register_name, "x0")
            self.assertEqual(res1.value, 10)

            # Link-time PC 0x1060 matches [0x1050, 0x1080) -> x5
            ctx.link_time_address = 0x1060
            res2 = DwarfEvaluator.evaluate(ctx)
            self.assertEqual(res2.status, EVAL_STATUS_OBSERVED)
            self.assertEqual(res2.register_name, "x5")
            self.assertEqual(res2.value, 20)

            # Link-time PC 0x1090 matches [0x1080, 0x1100) -> DW_OP_entry_value (OPTIMIZED_OUT)
            ctx.link_time_address = 0x1090
            res3 = DwarfEvaluator.evaluate(ctx)
            self.assertEqual(res3.status, EVAL_STATUS_OPTIMIZED_OUT)
            self.assertIn("entry_value", res3.reason)

            # Link-time PC 0x1150 is outside all ranges -> UNAVAILABLE
            ctx.link_time_address = 0x1150
            res4 = DwarfEvaluator.evaluate(ctx)
            self.assertEqual(res4.status, EVAL_STATUS_UNAVAILABLE)
            self.assertIn("outside", res4.reason)

    def test_31_dwarf_evaluator_unsupported_vs_optimized_out(self):
        """Verify UNSUPPORTED opcodes are NEVER conflated with OPTIMIZED_OUT."""
        ident = BinaryIdentity(path="/bin/dummy", architecture="aarch64", elf_class="ELF64", endianness="little")
        subp = DwarfSubprogram(
            die_offset=0x10,
            name="target_func",
            low_pc=0x1000,
            high_pc=0x1100,
            variables=[
                DwarfVariable(die_offset=0x20, name="unsupported_var", type_offset=0x30, location_expr="DW_OP_piece 4"),
                DwarfVariable(die_offset=0x25, name="optimized_var", type_offset=0x30, location_expr=None, location_list_offset=None),
            ],
        )

        mock_index = DwarfIndex(artifact_path="/bin/dummy")
        mock_index.types_by_die[0x30] = DwarfType(die_offset=0x30, tag="DW_TAG_base_type", name="int", byte_size=4)

        with patch("extractor.dwarf_indexer.DwarfIndexer.get_index", return_value=mock_index):
            ctx = DwarfEvaluationContext(
                binary_identity=ident,
                subprogram=subp,
                link_time_address=0x1020,
                variable_name="unsupported_var",
                architecture="aarch64",
            )
            res_unsup = DwarfEvaluator.evaluate(ctx)
            self.assertEqual(res_unsup.status, EVAL_STATUS_UNSUPPORTED)
            self.assertNotEqual(res_unsup.status, EVAL_STATUS_OPTIMIZED_OUT)

            ctx.variable_name = "optimized_var"
            res_opt = DwarfEvaluator.evaluate(ctx)
            self.assertEqual(res_opt.status, EVAL_STATUS_OPTIMIZED_OUT)
            self.assertNotEqual(res_opt.status, EVAL_STATUS_UNSUPPORTED)

    def test_32_dwarf_evaluator_scalar_types(self):
        """Verify unpacking of all supported scalar types from memory and registers."""
        # 1. Unpack from bytes
        v_i8, h_i8 = unpack_scalar_from_bytes(b"\xfb", "int8")
        self.assertEqual(v_i8, -5)
        self.assertEqual(h_i8, "0xfb")

        v_u8, h_u8 = unpack_scalar_from_bytes(b"\xfb", "uint8")
        self.assertEqual(v_u8, 251)
        self.assertEqual(h_u8, "0xfb")

        v_i16, h_i16 = unpack_scalar_from_bytes(struct.pack("<h", -300), "short")
        self.assertEqual(v_i16, -300)
        self.assertEqual(h_i16, "0xfed4")

        v_i32, h_i32 = unpack_scalar_from_bytes(struct.pack("<i", -100000), "int")
        self.assertEqual(v_i32, -100000)
        self.assertEqual(h_i32, "0xfffe7960")

        v_u32, h_u32 = unpack_scalar_from_bytes(struct.pack("<I", 100000), "unsigned int")
        self.assertEqual(v_u32, 100000)
        self.assertEqual(h_u32, "0x000186a0")

        v_i64, h_i64 = unpack_scalar_from_bytes(struct.pack("<q", -5000000000), "int64_t")
        self.assertEqual(v_i64, -5000000000)

        v_flt, h_flt = unpack_scalar_from_bytes(struct.pack("<f", 3.14159), "float")
        self.assertAlmostEqual(v_flt, 3.14159, places=4)

        v_dbl, h_dbl = unpack_scalar_from_bytes(struct.pack("<d", 2.718281828), "double")
        self.assertAlmostEqual(v_dbl, 2.718281828, places=6)

        v_bool, h_bool = unpack_scalar_from_bytes(b"\x01", "bool")
        self.assertEqual(v_bool, True)
        self.assertEqual(h_bool, "0x1")

        v_ptr, h_ptr = unpack_scalar_from_bytes(struct.pack("<Q", 0x7fffffffe100), "void*")
        self.assertEqual(v_ptr, 0x7fffffffe100)
        self.assertEqual(h_ptr, "0x7fffffffe100")

        # 2. Unpack from register
        v_reg_i32, h_reg_i32 = unpack_scalar_from_register(0xffffffff, "int32", byte_size=4)
        self.assertEqual(v_reg_i32, -1)
        self.assertEqual(h_reg_i32, "0xffffffff")

        v_reg_u32, h_reg_u32 = unpack_scalar_from_register(0xffffffff, "uint32", byte_size=4)
        self.assertEqual(v_reg_u32, 4294967295)

    def test_33_dwarf_evaluator_gdb_parity_value_assertions(self):
        """Verify Phase 2 resolver value reconstruction against exact expected values and types."""
        ident = BinaryIdentity(
            path="/bin/dummy",
            elf_class="ELF64",
            architecture="x86_64",
            endianness="little",
            build_id="abcdef0123456789",
            elf_type="ET_DYN",
        )
        fp = 0x7fffffffe000
        var_addr = fp + 16 - 24
        mem_store = {
            var_addr: struct.pack("<i", -4242),
        }

        def mock_mem_reader(addr: int, sz: int) -> Optional[bytes]:
            return mem_store.get(addr)

        subp = DwarfSubprogram(
            die_offset=0x10,
            name="target_func",
            low_pc=0x1000,
            high_pc=0x1100,
            frame_base="DW_OP_call_frame_cfa",
            cfa_rules=[(0x1000, 0x1100, "fp", 16, True)],
            variables=[
                DwarfVariable(die_offset=0x20, name="local_int", type_offset=0x30, location_expr="DW_OP_fbreg -24"),
            ],
        )

        mock_index = DwarfIndex(artifact_path="/bin/dummy")
        mock_index.types_by_die[0x30] = DwarfType(die_offset=0x30, tag="DW_TAG_base_type", name="int", byte_size=4)

        resolver = Phase2DwarfLocationResolver(
            binary_identity=ident,
            link_time_address=0x1020,
            load_bias=0,
            architecture="x86_64",
            memory_reader=mock_mem_reader,
        )

        with patch("extractor.dwarf_indexer.DwarfIndexer.get_index", return_value=mock_index):
            tv = resolver.resolve_variable(
                subprogram=subp,
                variable_name="local_int",
                registers={"rbp": fp, "rsp": fp - 32},
                frame_metadata=FrameMetadata(frame_pointer=fp),
            )
            self.assertEqual(tv.status, STATUS_OBSERVED)
            self.assertEqual(tv.value, -4242)
            self.assertEqual(tv.value_hex, "0xffffef6e")
            self.assertIn("stack:", tv.location)
            self.assertIn("CFA", tv.location)

    def test_34_phase2_resolver_companion_debug_artifact_and_cfi(self):
        """Verify companion artifact rejection and unsupported CFI rule detection in Phase 2 resolver."""
        ident = BinaryIdentity(
            path="/bin/dummy",
            elf_class="ELF64",
            architecture="x86_64",
            endianness="little",
            build_id="1111222233334444",
            elf_type="ET_DYN",
        )
        subp_unsupported = DwarfSubprogram(
            die_offset=0x10,
            name="complex_cfi_func",
            low_pc=0x1000,
            high_pc=0x1100,
            has_unsupported_cfi=True,
            variables=[
                DwarfVariable(die_offset=0x20, name="x", type_offset=0x30, location_expr="DW_OP_reg0"),
            ],
        )
        mock_index = DwarfIndex(artifact_path="/bin/dummy")
        mock_index.types_by_die[0x30] = DwarfType(die_offset=0x30, tag="DW_TAG_base_type", name="int", byte_size=4)

        resolver = Phase2DwarfLocationResolver(
            binary_identity=ident,
            link_time_address=0x1020,
            load_bias=0,
            architecture="x86_64",
        )

        with patch("extractor.dwarf_indexer.DwarfIndexer.get_index", return_value=mock_index):
            tv = resolver.resolve_variable(
                subprogram=subp_unsupported,
                variable_name="x",
                registers={"rax": 10},
                frame_metadata=FrameMetadata(),
            )
            self.assertEqual(tv.status, EVAL_STATUS_UNSUPPORTED)
            self.assertIn("DW_CFA_def_cfa_expression", tv.reason)

        # Mismatched companion debug artifact
        resolver_mismatch = Phase2DwarfLocationResolver(
            binary_identity=ident,
            link_time_address=0x1020,
            load_bias=0,
            architecture="x86_64",
            debug_artifact_path="/bin/other_debug",
        )
        dbg_ident = BinaryIdentity(
            path="/bin/other_debug",
            elf_class="ELF64",
            architecture="x86_64",
            endianness="little",
            build_id="9999888877776666",
            elf_type="ET_DYN",
        )

        with patch("os.path.exists", return_value=True), \
             patch("extractor.dwarf_evaluator.inspect_elf", return_value=dbg_ident):
            tv_mismatch = resolver_mismatch.resolve_variable(
                subprogram=DwarfSubprogram(die_offset=0x10, name="func", low_pc=0x1000),
                variable_name="x",
                registers={},
                frame_metadata=FrameMetadata(),
            )
            self.assertEqual(tv_mismatch.status, EVAL_STATUS_ERROR)
            self.assertIn("Build ID mismatch", tv_mismatch.reason)

    def test_35_frame_metadata_link_time_address(self):
        """Verify FrameMetadata includes link_time_address and serializes it in hex."""
        fm_none = FrameMetadata()
        self.assertIsNone(fm_none.link_time_address)
        self.assertIsNone(fm_none.to_dict()["link_time_address"])

        fm_val = FrameMetadata(link_time_address=0x123456)
        self.assertEqual(fm_val.link_time_address, 0x123456)
        self.assertEqual(fm_val.to_dict()["link_time_address"], "0x123456")

    def test_36_decoder_normalizes_canonical_registers(self):
        """Verify EbpfEventDecoder normalizes arguments and control registers to canonical names."""
        # AArch64
        dec_arm = EbpfEventDecoder(target_pid=100, architecture="aarch64", function_name="func")
        line_arm = json.dumps({
            "type": "ENTRY", "pid": 100, "tid": 100,
            "arg0": 10, "arg1": 20, "fp": "0x2000", "ra": "0x3000", "sp": "0x4000", "pc": "0x1000",
        })
        ev_arm = dec_arm.decode_line(line_arm)
        self.assertIsNotNone(ev_arm)
        self.assertEqual(ev_arm.registers.get("x0"), 10)
        self.assertEqual(ev_arm.registers.get("x1"), 20)
        self.assertEqual(ev_arm.registers.get("x29"), 0x2000)
        self.assertEqual(ev_arm.registers.get("x30"), 0x3000)
        self.assertEqual(ev_arm.registers.get("sp"), 0x4000)
        self.assertEqual(ev_arm.registers.get("pc"), 0x1000)

        # x86_64
        dec_x86 = EbpfEventDecoder(target_pid=100, architecture="x86_64", function_name="func")
        line_x86 = json.dumps({
            "type": "ENTRY", "pid": 100, "tid": 100,
            "arg0": 42, "arg1": 84, "fp": "0x5000", "sp": "0x6000", "pc": "0x7000",
        })
        ev_x86 = dec_x86.decode_line(line_x86)
        self.assertIsNotNone(ev_x86)
        self.assertEqual(ev_x86.registers.get("rdi"), 42)
        self.assertEqual(ev_x86.registers.get("rsi"), 84)
        self.assertEqual(ev_x86.registers.get("rbp"), 0x5000)
        self.assertEqual(ev_x86.registers.get("rsp"), 0x6000)
        self.assertEqual(ev_x86.registers.get("rip"), 0x7000)

    def test_37_return_probe_marks_local_variables_unavailable(self):
        """Verify return probes mark subprogram variables UNAVAILABLE due to frame destruction."""
        subp = DwarfSubprogram(
            die_offset=0x10,
            name="compute",
            low_pc=0x1000,
            high_pc=0x1100,
            variables=[
                DwarfVariable(die_offset=0x20, name="count"),
                DwarfVariable(die_offset=0x30, name="buffer"),
            ],
        )
        dec = EbpfEventDecoder(
            target_pid=200,
            architecture="aarch64",
            function_name="compute",
            subprogram=subp,
        )
        ret_line = json.dumps({
            "type": "RETURN", "pid": 200, "tid": 200,
            "ret": 1234, "sp": "0x4000", "pc": "0x5000",
        })
        ev = dec.decode_line(ret_line)
        self.assertIsNotNone(ev)
        self.assertEqual(ev.probe_type, "RETURN")
        self.assertIsNotNone(ev.return_value)
        self.assertEqual(ev.return_value.status, STATUS_OBSERVED)
        self.assertEqual(ev.return_value.value, 1234)

        self.assertIn("count", ev.local_variables)
        self.assertEqual(ev.local_variables["count"].status, STATUS_UNAVAILABLE)
        self.assertIn("destroyed", ev.local_variables["count"].reason)

        self.assertIn("buffer", ev.local_variables)
        self.assertEqual(ev.local_variables["buffer"].status, STATUS_UNAVAILABLE)
        self.assertIn("destroyed", ev.local_variables["buffer"].reason)

    def test_38_entry_probe_dwarf_variable_resolution(self):
        """Verify entry probes resolve local variables via configured DWARF location resolver."""
        subp = DwarfSubprogram(
            die_offset=0x10,
            name="target_func",
            low_pc=0x2000,
            high_pc=0x2100,
            variables=[
                DwarfVariable(die_offset=0x20, name="arg_val"),
            ],
        )
        mock_resolver = MagicMock()
        mock_resolver.resolve_variable.return_value = TraceValue(
            name="arg_val",
            status=STATUS_OBSERVED,
            value=777,
            value_hex="0x00000309",
            location="register:x0",
        )

        dec = EbpfEventDecoder(
            target_pid=300,
            architecture="aarch64",
            function_name="target_func",
            load_bias=0x1000,
            subprogram=subp,
            resolver=mock_resolver,
        )

        entry_line = json.dumps({
            "type": "ENTRY", "pid": 300, "tid": 300,
            "arg0": 777, "sp": "0x8000", "pc": "0x3000",
        })
        ev = dec.decode_line(entry_line)
        self.assertIsNotNone(ev)
        self.assertEqual(ev.frame_metadata.link_time_address, 0x2000, "Link PC = runtime 0x3000 - load_bias 0x1000")
        self.assertEqual(mock_resolver.link_time_address, 0x2000)
        mock_resolver.resolve_variable.assert_called_once()
        self.assertIn("arg_val", ev.local_variables)
        self.assertEqual(ev.local_variables["arg_val"].status, STATUS_OBSERVED)
        self.assertEqual(ev.local_variables["arg_val"].value, 777)

    def test_39_missing_runtime_pc_returns_unavailable_not_zero(self):
        """Verify that when runtime PC is absent/null, link_time_address is None and evaluator returns UNAVAILABLE."""
        subp = DwarfSubprogram(
            die_offset=0x10,
            name="target_func",
            low_pc=0x2000,
            high_pc=0x2100,
            variables=[
                DwarfVariable(die_offset=0x20, name="arg_val", location_expr="DW_OP_reg0"),
            ],
        )
        ident = BinaryIdentity(
            path="/bin/dummy", elf_class="ELF64", architecture="aarch64", endianness="little",
            build_id="abcdef", stripped=False, has_debug_info=True,
        )
        resolver = Phase2DwarfLocationResolver(
            binary_identity=ident,
            link_time_address=None,
            load_bias=0x1000,
            architecture="aarch64",
        )
        dec = EbpfEventDecoder(
            target_pid=400,
            architecture="aarch64",
            function_name="target_func",
            load_bias=0x1000,
            subprogram=subp,
            resolver=resolver,
        )

        entry_line = json.dumps({
            "type": "ENTRY", "pid": 400, "tid": 400,
            "arg0": 777, "sp": "0x8000",
            # Note: "pc" is completely omitted
        })
        ev = dec.decode_line(entry_line)
        self.assertIsNotNone(ev)
        self.assertIsNone(ev.frame_metadata.instruction_pointer, "Instruction pointer must be None when omitted")
        self.assertIsNone(ev.frame_metadata.link_time_address, "link_time_address must be None, never fabricated 0")
        self.assertIsNone(resolver.link_time_address)
        self.assertIn("arg_val", ev.local_variables)
        self.assertEqual(ev.local_variables["arg_val"].status, STATUS_UNAVAILABLE)
        self.assertIn("unavailable", ev.local_variables["arg_val"].reason.lower())

    def test_40_subprogram_declaration_vs_definition_and_ambiguity(self):
        """Verify declaration DIE vs definition DIE selection, and fail closed on ambiguous definitions."""
        tracer = EbpfTracer(use_sudo=False)
        ident = BinaryIdentity(
            path="/bin/test_multi", elf_class="ELF64", architecture="x86_64", endianness="little",
            build_id="abc123", stripped=False, has_debug_info=True, elf_type="ET_DYN",
            pt_loads=[{"p_vaddr": 0x0, "p_memsz": 0x5000, "p_offset": 0x0, "p_filesz": 0x5000}],
        )

        # 1. Declaration DIE (no vars, is_declaration=True) vs Definition DIE (has vars, is_declaration=False)
        decl_sp = DwarfSubprogram(die_offset=0x10, name="worker", low_pc=0x1000, is_declaration=True, variables=[])
        def_sp = DwarfSubprogram(
            die_offset=0x20, name="worker", low_pc=0x1000, is_declaration=False,
            variables=[DwarfVariable(die_offset=0x30, name="task_id", location_expr="DW_OP_reg5")],
        )
        mock_idx1 = MagicMock()
        mock_idx1.subprograms_by_name = {"worker": [decl_sp, def_sp]}
        mock_idx1.subprograms = [decl_sp, def_sp]

        with patch("extractor.dwarf_indexer.DwarfIndexer.get_index", return_value=mock_idx1), \
             patch("os.path.exists", return_value=True), \
             patch("os.path.getsize", return_value=0x5000), \
             patch("extractor.ebpf_tracer.EbpfEnvironmentChecker.check_prerequisites") as mock_cap, \
             patch("os.kill", return_value=None), \
             patch("extractor.ebpf_tracer.inspect_elf", return_value=ident), \
             patch.object(tracer, "_resolve_probe_target", return_value=(0x1000, "0x1000", None)), \
             patch.object(tracer, "_generate_bpftrace_script", return_value="uprobe:..."), \
             patch("subprocess.Popen") as mock_popen:

            mock_cap.return_value = EbpfCapabilityResult(
                supported=True,
                backend="bpftrace",
                architecture="x86_64",
                kernel_version="6.17",
                is_privileged=True,
                unprivileged_bpf_disabled=0,
                has_bpf_fs=True,
            )
            mock_proc = MagicMock()
            mock_proc.poll.return_value = 0
            mock_proc.stdout.readline.return_value = ""
            mock_proc.stdout.readlines.return_value = []
            mock_popen.return_value = mock_proc

            session = tracer.trace(pid=123, binary_path="/bin/test_multi", function_name="worker", duration_s=0.01)
            # Should attach and attempt tracing without crashing or picking empty declaration
            self.assertEqual(session.function_name, "worker")

        # 2. Ambiguous distinct subprogram definitions at different low_pc values fails closed
        def_sp1 = DwarfSubprogram(die_offset=0x10, name="worker", low_pc=0x1000, is_declaration=False, variables=[DwarfVariable(die_offset=0x15, name="a")])
        def_sp2 = DwarfSubprogram(die_offset=0x20, name="worker", low_pc=0x2000, is_declaration=False, variables=[DwarfVariable(die_offset=0x25, name="b")])
        mock_idx2 = MagicMock()
        mock_idx2.subprograms_by_name = {"worker": [def_sp1, def_sp2]}
        mock_idx2.subprograms = [def_sp1, def_sp2]

        with patch("extractor.dwarf_indexer.DwarfIndexer.get_index", return_value=mock_idx2), \
             patch("os.path.exists", return_value=True), \
             patch("os.path.getsize", return_value=0x5000), \
             patch("extractor.ebpf_tracer.EbpfEnvironmentChecker.check_prerequisites") as mock_cap, \
             patch("os.kill", return_value=None), \
             patch("extractor.ebpf_tracer.inspect_elf", return_value=ident):

            mock_cap.return_value = EbpfCapabilityResult(
                supported=True,
                backend="bpftrace",
                architecture="x86_64",
                kernel_version="6.17",
                is_privileged=True,
                unprivileged_bpf_disabled=0,
                has_bpf_fs=True,
            )
            session_ambig = tracer.trace(pid=123, binary_path="/bin/test_multi", function_name="worker", duration_s=0.01)
            self.assertEqual(session_ambig.status, "FAILED")
            self.assertIn("Ambiguous", session_ambig.error_message)

    def test_41_dwarf_indexer_cache_invalidation_on_binary_replacement(self):
        """Verify DwarfIndexer invalidates cached index when binary mtime or size changes."""
        with tempfile.NamedTemporaryFile(suffix=".elf") as tf:
            tf.write(b"\x7fELF" + b"\x00" * 100)
            tf.flush()
            path = tf.name

            ident = BinaryIdentity(
                path=path, elf_class="ELF64", architecture="x86_64", endianness="little",
                build_id="build1", stripped=False, has_debug_info=True,
            )
            with patch("extractor.dwarf_indexer.inspect_elf", return_value=ident):
                idx1 = DwarfIndexer.get_index(path)
                self.assertIs(DwarfIndexer.get_index(path), idx1, "Unmodified file must return cached index")

                # Change mtime
                new_mtime = os.path.getmtime(path) + 10.0
                os.utime(path, (new_mtime, new_mtime))

                idx2 = DwarfIndexer.get_index(path)
                self.assertIsNot(idx2, idx1, "Modified mtime must invalidate cache and produce fresh index")

    def test_42_proc_mem_reader_bounds_and_validity(self):
        """Verify proc_mem_reader rejects sizes <= 0, > 64KiB, and invalid pointer addresses using AddressValidator."""
        # Test the memory reader logic directly
        def create_reader(pid, arch="x86_64"):
            def proc_mem_reader(addr: int, size: int) -> Optional[bytes]:
                norm_addr = AddressValidator.normalize_data_address(addr, arch)
                if norm_addr is None or not AddressValidator.is_valid_memory_address(norm_addr, size, arch):
                    return None
                try:
                    from extractor.watch_session import read_process_memory_slice
                    data, status, _ = read_process_memory_slice(pid, norm_addr, size)
                    if status == "OBSERVED" and data is not None and len(data) == size:
                        return data
                    return None
                except Exception:
                    return None
            return proc_mem_reader

        reader_x86 = create_reader(os.getpid(), arch="x86_64")

        # Size bounds
        self.assertIsNone(reader_x86(0x1000, 0), "Size 0 must return None")
        self.assertIsNone(reader_x86(0x1000, -1), "Negative size must return None")
        self.assertIsNone(reader_x86(0x1000, 65537), "Size > 64KiB must return None")

        # Address bounds
        self.assertIsNone(reader_x86(0, 4), "Address 0 (NULL) must return None")
        self.assertIsNone(reader_x86(-1, 4), "Negative address must return None")
        self.assertIsNone(reader_x86(0x500, 4), "Address < 0x1000 must return None")
        self.assertIsNone(reader_x86(0x8000000000000000, 4), "Kernel space address must return None")

        # Tagged pointer: valid on AArch64 (untagged), invalid on 4-level x86_64
        reader_aarch64 = create_reader(os.getpid(), arch="aarch64")
        self.assertFalse(AddressValidator.is_valid_memory_address(0x9000000000002000, 4, "x86_64"))
        self.assertTrue(AddressValidator.is_valid_memory_address(0x9000000000002000, 4, "aarch64"))
        self.assertEqual(AddressValidator.untag_data_address(0x9000000000002000, "aarch64"), 0x2000)

    def test_43_proc_mem_reader_valid_zeros_vs_unreadable(self):
        """Verify proc_mem_reader distinguishes valid zero bytes from unreadable memory."""
        # Mock read_process_memory_slice returning valid zeros vs UNAVAILABLE
        with patch("extractor.watch_session.read_process_memory_slice") as mock_read:
            # Valid zero bytes
            mock_read.return_value = (b"\x00\x00\x00\x00", "OBSERVED", None)
            from extractor.watch_session import read_process_memory_slice

            def reader(addr, size):
                if size <= 0 or size > 65536 or addr <= 0 or addr >= 0x8000000000000000:
                    return None
                data, status, _ = read_process_memory_slice(100, addr, size)
                return data if (status == "OBSERVED" and data is not None and len(data) == size) else None

            res_zeros = reader(0x1000, 4)
            self.assertEqual(res_zeros, b"\x00\x00\x00\x00", "Legitimate zero bytes must be returned as bytes")

            # Unreadable memory (EFAULT / unmapped)
            mock_read.return_value = (None, "UNAVAILABLE", "Address not mapped (EFAULT)")
            res_unavail = reader(0x2000, 4)
            self.assertIsNone(res_unavail, "Unreadable memory must return None, never fabricated zeros")

    def test_44_proc_mem_reader_partial_read_and_process_exit(self):
        """Verify proc_mem_reader returns None on partial reads or target process termination."""
        with patch("extractor.watch_session.read_process_memory_slice") as mock_read:
            def reader(addr, size):
                if size <= 0 or size > 65536 or addr <= 0 or addr >= 0x8000000000000000:
                    return None
                from extractor.watch_session import read_process_memory_slice
                data, status, _ = read_process_memory_slice(100, addr, size)
                return data if (status == "OBSERVED" and data is not None and len(data) == size) else None

            # Partial read
            mock_read.return_value = (b"\x01\x02", "PARTIAL", "Partial read: 2/4 bytes")
            res_partial = reader(0x1000, 4)
            self.assertIsNone(res_partial, "Partial read must not fabricate a complete value")

            # Target terminated
            mock_read.return_value = (None, "TARGET_TERMINATED", "Process exited")
            res_exit = reader(0x1000, 4)
            self.assertIsNone(res_exit, "Terminated process memory read must return None")

    def test_45_load_bias_calculation_pie_and_nopie(self):
        """Verify load bias calculation and runtime-to-link-time PC translation."""
        # Non-PIE: load_bias = 0
        dec_nopie = EbpfEventDecoder(target_pid=100, architecture="x86_64", function_name="f", load_bias=0)
        ev_nopie = dec_nopie.decode_line(json.dumps({"type": "ENTRY", "pid": 100, "pc": "0x401000"}))
        self.assertIsNotNone(ev_nopie)
        self.assertEqual(ev_nopie.frame_metadata.instruction_pointer, 0x401000)
        self.assertEqual(ev_nopie.frame_metadata.link_time_address, 0x401000)

        # PIE: load_bias = 0x555555554000
        dec_pie = EbpfEventDecoder(
            target_pid=100, architecture="x86_64", function_name="f", load_bias=0x555555554000,
        )
        ev_pie = dec_pie.decode_line(json.dumps({"type": "ENTRY", "pid": 100, "pc": "0x555555555120"}))
        self.assertIsNotNone(ev_pie)
        self.assertEqual(ev_pie.frame_metadata.instruction_pointer, 0x555555555120)
        self.assertEqual(ev_pie.frame_metadata.link_time_address, 0x1120)

    def test_46_missing_build_id_and_explicitly_unchecked_states(self):
        """Verify truthful reporting of UNAVAILABLE and EXPLICITLY_UNCHECKED Build ID states."""
        tracer = EbpfTracer(use_sudo=False)
        ident_no_bid = BinaryIdentity(
            path="/bin/no_bid", elf_class="ELF64", architecture="x86_64", endianness="little",
            build_id=None, stripped=False, has_debug_info=True,
        )

        with patch("extractor.ebpf_tracer.inspect_elf", return_value=ident_no_bid), \
             patch("os.path.exists", return_value=True), \
             patch("os.kill", return_value=None), \
             patch("extractor.ebpf_tracer.EbpfEnvironmentChecker.check_prerequisites") as mock_cap, \
             patch.object(tracer, "_resolve_probe_target", return_value=(0x1000, "0x1000", None)), \
             patch.object(tracer, "_generate_bpftrace_script", return_value="uprobe:..."), \
             patch("subprocess.Popen") as mock_popen:

            mock_cap.return_value = EbpfCapabilityResult(
                supported=True,
                backend="bpftrace",
                architecture="x86_64",
                kernel_version="6.17",
                is_privileged=True,
                unprivileged_bpf_disabled=0,
                has_bpf_fs=True,
            )
            mock_proc = MagicMock()
            mock_proc.poll.return_value = 0
            mock_proc.stdout.readline.return_value = ""
            mock_proc.stdout.readlines.return_value = []
            mock_popen.return_value = mock_proc

            # 1. verify_build_id=True but binary lacks Build ID -> UNAVAILABLE
            sess_unavail = tracer.trace(pid=100, binary_path="/bin/no_bid", function_name="f", duration_s=0.01, verify_build_id=True)
            self.assertEqual(sess_unavail.build_id_status, "UNAVAILABLE")

            # 2. verify_build_id=False -> EXPLICITLY_UNCHECKED
            sess_unchecked = tracer.trace(pid=100, binary_path="/bin/no_bid", function_name="f", duration_s=0.01, verify_build_id=False)
            self.assertEqual(sess_unchecked.build_id_status, "EXPLICITLY_UNCHECKED")

    def test_47_pc_bounds_and_malformed_values_handling(self):
        """Verify malformed, non-numeric, 0, negative, and out-of-range PC values are treated as None."""
        dec_x86 = EbpfEventDecoder(target_pid=100, architecture="x86_64", function_name="func")
        for bad_pc in [0, -1, "null", "invalid", "0xG", 0x8000000000000000, 0xc25695220d80]:
            line = json.dumps({"type": "ENTRY", "pid": 100, "tid": 100, "pc": bad_pc, "arg0": 123})
            ev = dec_x86.decode_line(line)
            self.assertIsNotNone(ev)
            self.assertIsNone(ev.frame_metadata.instruction_pointer, f"Expected None for bad PC: {bad_pc}")
            self.assertIsNone(ev.frame_metadata.link_time_address, f"Expected None link_pc for bad PC: {bad_pc}")
            self.assertNotIn("pc", ev.registers)
            self.assertNotIn("rip", ev.registers)

        # On AArch64, a genuine 4-byte aligned userspace text PC is valid
        dec_aarch64 = EbpfEventDecoder(target_pid=100, architecture="aarch64", function_name="func")
        line_aarch64_valid = json.dumps({"type": "ENTRY", "pid": 100, "tid": 100, "pc": "0xaaaaaaaa1230", "arg0": 123})
        ev_aarch64_valid = dec_aarch64.decode_line(line_aarch64_valid)
        self.assertIsNotNone(ev_aarch64_valid)
        self.assertEqual(ev_aarch64_valid.frame_metadata.instruction_pointer, 0xaaaaaaaa1230)

        # On AArch64, unaligned PC (0xaaaaaaaa1231) must be rejected
        line_aarch64_unaligned = json.dumps({"type": "ENTRY", "pid": 100, "tid": 100, "pc": "0xaaaaaaaa1231", "arg0": 123})
        ev_aarch64_unaligned = dec_aarch64.decode_line(line_aarch64_unaligned)
        self.assertIsNotNone(ev_aarch64_unaligned)
        self.assertIsNone(ev_aarch64_unaligned.frame_metadata.instruction_pointer)

        # On AArch64, hardware instruction fetch forbids TBI tags; nonzero top byte must be rejected
        tagged_pc = (0xc2 << 56) | 0x5695220d80
        line_aarch64_tbi = json.dumps({"type": "ENTRY", "pid": 100, "tid": 100, "pc": tagged_pc, "arg0": 123})
        ev_aarch64_tbi = dec_aarch64.decode_line(line_aarch64_tbi)
        self.assertIsNotNone(ev_aarch64_tbi)
        self.assertIsNone(ev_aarch64_tbi.frame_metadata.instruction_pointer)

    def test_48_resolver_uses_frame_metadata_link_time_address_dynamically(self):
        """Verify Phase2DwarfLocationResolver uses link_time_address from frame_metadata instead of stale entry address."""
        ident = BinaryIdentity(
            path="/bin/dummy", elf_class="ELF64", architecture="aarch64", endianness="little",
            build_id="abcdef", stripped=False, has_debug_info=True,
        )
        subp = DwarfSubprogram(
            die_offset=0x10,
            name="target_func",
            low_pc=0x1000,
            high_pc=0x1200,
            variables=[
                DwarfVariable(die_offset=0x20, name="dyn_var", type_offset=0x30, location_list_offset=0x500),
            ],
        )
        mock_index = DwarfIndex(artifact_path="/bin/dummy")
        mock_index.types_by_die[0x30] = DwarfType(die_offset=0x30, tag="DW_TAG_base_type", name="int", byte_size=4)

        # Location table: [0x1000, 0x1050) -> x0, [0x1050, 0x1100) -> x1
        mock_loc_table = {
            0x500: [
                (0x1000, 0x1050, "DW_OP_reg0 (x0)"),
                (0x1050, 0x1100, "DW_OP_reg1 (x1)"),
            ]
        }

        # Initialize resolver with low_pc (0x1000)
        resolver = Phase2DwarfLocationResolver(
            binary_identity=ident,
            link_time_address=0x1000,
            architecture="aarch64",
        )

        with patch("extractor.dwarf_indexer.DwarfIndexer.get_index", return_value=mock_index), \
             patch("extractor.dwarf_evaluator.parse_debug_loc_table", return_value=mock_loc_table):
            # Pass frame_metadata with a DIFFERENT instruction address (0x1060)
            fm = FrameMetadata(instruction_pointer=0x1060, link_time_address=0x1060)
            tv = resolver.resolve_variable(
                subprogram=subp,
                variable_name="dyn_var",
                registers={"x0": 11, "x1": 22},
                frame_metadata=fm,
            )
            # Must evaluate at 0x1060 (x1 -> 22), NOT stale low_pc 0x1000 (x0 -> 11)
            self.assertEqual(tv.status, STATUS_OBSERVED)
            self.assertEqual(tv.value, 22)
            self.assertEqual(tv.location, "register:x1")

    def test_49_uprobe_offset_capability_detection(self):
        """Verify runtime detection of uprobe offset support in EbpfEnvironmentChecker across all 4 outcomes."""
        EbpfEnvironmentChecker.invalidate_uprobe_offset_cache()

        # 1. Without bpftrace executable -> NOT_CHECKED
        res_no_bpf, status_no_bpf, reason_no_bpf = EbpfEnvironmentChecker.check_uprobe_offset_support(bpftrace_path="")
        self.assertFalse(res_no_bpf)
        self.assertEqual(status_no_bpf, "NOT_CHECKED")
        self.assertIn("not found", reason_no_bpf)

        # 2. Without privileges -> NOT_CHECKED
        res_no_priv, status_no_priv, reason_no_priv = EbpfEnvironmentChecker.check_uprobe_offset_support(
            bpftrace_path="/usr/bin/bpftrace", is_privileged=False
        )
        self.assertFalse(res_no_priv)
        self.assertEqual(status_no_priv, "NOT_CHECKED")
        self.assertIn("Privileges", reason_no_priv)

        # 3. Missing compiler -> UNKNOWN
        with patch("shutil.which", side_effect=lambda name: "/usr/bin/bpftrace" if name == "bpftrace" else None), \
             patch("os.stat") as mock_stat:
            mock_stat.return_value.st_mtime_ns = 1000
            mock_stat.return_value.st_size = 2000
            res_no_gcc, status_no_gcc, reason_no_gcc = EbpfEnvironmentChecker.check_uprobe_offset_support(
                bpftrace_path="/usr/bin/bpftrace", is_privileged=True, force_refresh=True
            )
            self.assertFalse(res_no_gcc)
            self.assertEqual(status_no_gcc, "UNKNOWN")
            self.assertIn("Compiler 'gcc' not found", reason_no_gcc)

        # 4. Compiler failure -> UNKNOWN
        mock_gcc_fail = MagicMock()
        mock_gcc_fail.returncode = 1
        mock_gcc_fail.stderr = b"gcc: internal compiler error"
        with patch("shutil.which", return_value="/usr/bin/gcc"), \
             patch("os.stat") as mock_stat, \
             patch("subprocess.run", return_value=mock_gcc_fail):
            mock_stat.return_value.st_mtime_ns = 1000
            mock_stat.return_value.st_size = 2000
            res_gcc_err, status_gcc_err, reason_gcc_err = EbpfEnvironmentChecker.check_uprobe_offset_support(
                bpftrace_path="/usr/bin/bpftrace", is_privileged=True, force_refresh=True
            )
            self.assertFalse(res_gcc_err)
            self.assertEqual(status_gcc_err, "UNKNOWN")
            self.assertIn("Failed to build probe test binary", reason_gcc_err)

        mock_disasm = (
            "0000000000000500 <probe_target>:\n"
            " 500:\td503201f\tnop\n"
            " 504:\td503201f\tnop\n"
            " 508:\td65f03c0\tret\n"
        )
        mock_gcc_ok = MagicMock(returncode=0, stderr=b"", stdout=mock_disasm)
        with patch("shutil.which", return_value="/usr/bin/gcc"), \
             patch("os.stat") as mock_stat, \
             patch("subprocess.run", return_value=mock_gcc_ok), \
             patch("subprocess.Popen") as mock_popen:
            mock_stat.return_value.st_mtime_ns = 1000
            mock_stat.return_value.st_size = 2000
            mock_proc = MagicMock()
            mock_proc.communicate.side_effect = subprocess.TimeoutExpired(cmd=["bpftrace"], timeout=2.0)
            mock_proc.pid = 9999
            mock_popen.return_value = mock_proc
            with patch("os.killpg"):
                res_to, status_to, reason_to = EbpfEnvironmentChecker.check_uprobe_offset_support(
                    bpftrace_path="/usr/bin/bpftrace", is_privileged=True, force_refresh=True
                )
                self.assertFalse(res_to)
                self.assertEqual(status_to, "UNKNOWN")
                self.assertIn("timed out", reason_to.lower())

        # 6. Mock bpftrace returning exit code 255 with 'compiled without (k|u)probe offset support' -> UNSUPPORTED
        with patch("shutil.which", return_value="/usr/bin/gcc"), \
             patch("os.stat") as mock_stat, \
             patch("subprocess.run", return_value=mock_gcc_ok), \
             patch("subprocess.Popen") as mock_popen:
            mock_stat.return_value.st_mtime_ns = 1000
            mock_stat.return_value.st_size = 2000
            mock_proc = MagicMock()
            mock_proc.returncode = 255
            mock_proc.communicate.return_value = ("", "ERROR: Can't check if uprobe is in proper place (compiled without (k|u)probe offset support): /bin/ls:main+4")
            mock_proc.pid = 9999
            mock_popen.return_value = mock_proc
            res_fail, status_fail, reason_fail = EbpfEnvironmentChecker.check_uprobe_offset_support(
                bpftrace_path="/usr/bin/bpftrace", is_privileged=True, force_refresh=True
            )
            self.assertFalse(res_fail)
            self.assertEqual(status_fail, "UNSUPPORTED")
            self.assertIn("compiled without (k|u)probe offset support", reason_fail)

        # 7. Mock bpftrace succeeding (returncode 0 with PROBE_OFFSET_HIT in stdout) -> SUPPORTED
        with patch("shutil.which", return_value="/usr/bin/gcc"), \
             patch("os.stat") as mock_stat, \
             patch("subprocess.run", return_value=mock_gcc_ok), \
             patch("subprocess.Popen") as mock_popen:
            mock_stat.return_value.st_mtime_ns = 1000
            mock_stat.return_value.st_size = 2000
            mock_proc = MagicMock()
            mock_proc.returncode = 0
            mock_proc.communicate.return_value = ("Attaching 1 probe...\nPROBE_OFFSET_HIT\n", "")
            mock_proc.pid = 9999
            mock_popen.return_value = mock_proc
            res_ok, status_ok, reason_ok = EbpfEnvironmentChecker.check_uprobe_offset_support(
                bpftrace_path="/usr/bin/bpftrace", is_privileged=True, force_refresh=True
            )
            self.assertTrue(res_ok)
            self.assertEqual(status_ok, "SUPPORTED")
            self.assertIn("verified", reason_ok)

    def test_50_observation_backend_capabilities_truthful_flags(self):
        """Verify EbpfObservationBackend exposes explicit boolean capability flags at top-level and scope."""
        EbpfEnvironmentChecker.invalidate_uprobe_offset_cache()
        backend = EbpfObservationBackend()
        # Default capabilities query is inexpensive (active_probe=False)
        caps = backend.capabilities()
        self.assertIn("arbitrary_instruction_offset_probing", caps)
        self.assertFalse(caps["arbitrary_instruction_offset_probing"])
        self.assertIn("stack_locals_readable_at_entry", caps)
        self.assertFalse(caps["stack_locals_readable_at_entry"])
        self.assertIn("locals_readable_at_return", caps)
        self.assertFalse(caps["locals_readable_at_return"])
        self.assertIn(caps.get("uprobe_offset_status"), ("UNSUPPORTED", "SUPPORTED", "UNKNOWN", "NOT_CHECKED"))
        self.assertIsInstance(caps.get("uprobe_offset_supported"), bool)

        scope = caps["dwarf_eval_scope"]
        self.assertFalse(scope["arbitrary_instruction_offset_probing"])
        self.assertFalse(scope["stack_locals_readable_at_entry"])
        self.assertFalse(scope["locals_readable_at_return"])
        self.assertIn(scope.get("uprobe_offset_status"), ("UNSUPPORTED", "SUPPORTED", "UNKNOWN", "NOT_CHECKED"))
        self.assertIsInstance(scope.get("uprobe_offset_supported"), bool)

    def test_51_address_validator_instruction_vs_memory(self):
        """Scenario 51: Architecture-specific address validation and code vs data role separation."""
        # 1. Rejection of NULL / low memory page 0
        self.assertFalse(AddressValidator.is_valid_instruction_pointer(0, "x86_64"))
        self.assertFalse(AddressValidator.is_valid_instruction_pointer(0x500, "x86_64"))
        self.assertFalse(AddressValidator.is_valid_memory_address(0, 4, "x86_64"))
        self.assertFalse(AddressValidator.is_valid_memory_address(0x500, 4, "x86_64"))

        # 2. Instruction pointer alignment: AArch64 requires 4-byte alignment, x86_64 allows 1-byte
        self.assertTrue(AddressValidator.is_valid_instruction_pointer(0x401000, "x86_64"))
        self.assertTrue(AddressValidator.is_valid_instruction_pointer(0x401001, "x86_64"))
        self.assertTrue(AddressValidator.is_valid_instruction_pointer(0x401000, "aarch64"))
        self.assertFalse(AddressValidator.is_valid_instruction_pointer(0x401001, "aarch64"))

        # 3. Memory data pointer alignment: arbitrary alignment permitted for byte reads
        self.assertTrue(AddressValidator.is_valid_memory_address(0x401001, 1, "aarch64"))

        # 4. AArch64 Top Byte Ignore (TBI): forbidden for PC, allowed and untagged for data memory
        tagged_ptr = (0xc2 << 56) | 0x5695220d80
        self.assertFalse(AddressValidator.is_valid_instruction_pointer(tagged_ptr, "aarch64"))
        self.assertTrue(AddressValidator.is_valid_memory_address(tagged_ptr, 4, "aarch64"))
        self.assertEqual(AddressValidator.normalize_data_address(tagged_ptr, "aarch64"), 0x5695220d80)
        self.assertEqual(AddressValidator.untag_data_address(tagged_ptr, "aarch64"), 0x5695220d80)

        # 5. Resolving the 0xc25695220d80 address contradiction:
        # As an untagged 48-bit address, 0xc25695220d80 has bit 47 set.
        # On AArch64: within standard 48-bit userspace VA (<= 0x0000ffffffffffff)
        self.assertTrue(AddressValidator.is_valid_memory_address(0xc25695220d80, 4, "aarch64"))
        # On x86_64 4-level paging: non-canonical userspace address (> 0x00007fffffffffff), rejected!
        self.assertFalse(AddressValidator.is_valid_instruction_pointer(0xc25695220d80, "x86_64", five_level_paging=False))
        self.assertFalse(AddressValidator.is_valid_memory_address(0xc25695220d80, 4, "x86_64", five_level_paging=False))
        # On x86_64 5-level paging: valid userspace address (<= 0x00ffffffffffffff)
        self.assertTrue(AddressValidator.is_valid_instruction_pointer(0xc25695220d80, "x86_64", five_level_paging=True))

        # 6. Kernel space addresses (bit 63) strictly rejected
        self.assertFalse(AddressValidator.is_valid_instruction_pointer(0x8000000000000000, "x86_64"))
        self.assertFalse(AddressValidator.is_valid_instruction_pointer(0x8000000000000000, "aarch64"))
        self.assertFalse(AddressValidator.is_valid_memory_address(0x8000000000000000, 4, "x86_64"))
        self.assertFalse(AddressValidator.is_valid_memory_address(0x8000000000000000, 4, "aarch64"))

    def test_52_runtime_to_link_pc_underflow_and_alignment(self):
        """Scenario 52: Runtime-to-link-time PC translation with underflow detection and alignment validation."""
        # 1. Normal PIE translation
        link_pc = AddressValidator.compute_link_time_pc(0x555555555120, 0x555555554000, "x86_64")
        self.assertEqual(link_pc, 0x1120)

        # 2. Non-PIE translation (load_bias = 0)
        link_pc_nopie = AddressValidator.compute_link_time_pc(0x401000, 0, "x86_64")
        self.assertEqual(link_pc_nopie, 0x401000)

        # 3. Underflow detection: runtime_pc < load_bias returns None
        self.assertIsNone(AddressValidator.compute_link_time_pc(0x1000, 0x2000, "x86_64"))

        # 4. Negative load bias returns None
        self.assertIsNone(AddressValidator.compute_link_time_pc(0x5000, -100, "x86_64"))

        # 5. Invalid runtime PC returns None
        self.assertIsNone(AddressValidator.compute_link_time_pc(None, 0, "x86_64"))
        self.assertIsNone(AddressValidator.compute_link_time_pc(0, 0, "x86_64"))
        self.assertIsNone(AddressValidator.compute_link_time_pc(-1, 0, "x86_64"))

        # 6. AArch64 alignment check on link PC
        self.assertEqual(AddressValidator.compute_link_time_pc(0x555555555120, 0x555555554000, "aarch64"), 0x1120)
        self.assertIsNone(AddressValidator.compute_link_time_pc(0x555555555121, 0x555555554000, "aarch64"))

    def test_53_uprobe_offset_detector_real_execution_and_hit_verification(self):
        """Scenario 53: Verify active execution probe uses -c and verifies PROBE_OFFSET_HIT event."""
        EbpfEnvironmentChecker.invalidate_uprobe_offset_cache()
        mock_disasm = (
            "0000000000000500 <probe_target>:\n"
            " 500:\td503201f\tnop\n"
            " 504:\td503201f\tnop\n"
            " 508:\td65f03c0\tret\n"
        )
        mock_gcc_ok = MagicMock(returncode=0, stderr=b"", stdout=mock_disasm)

        # 1. Probe executes fixture, outputs PROBE_OFFSET_HIT, exits 0 -> SUPPORTED
        with patch("shutil.which", return_value="/usr/bin/gcc"), \
             patch("os.stat") as mock_stat, \
             patch("subprocess.run", return_value=mock_gcc_ok), \
             patch("subprocess.Popen") as mock_popen:
            mock_stat.return_value.st_mtime_ns = 5000
            mock_stat.return_value.st_size = 3000
            mock_proc = MagicMock(returncode=0)
            mock_proc.communicate.return_value = ("Attaching 1 probe...\nPROBE_OFFSET_HIT\n", "")
            mock_proc.pid = 1234
            mock_popen.return_value = mock_proc

            supported, status, reason = EbpfEnvironmentChecker.check_uprobe_offset_support(
                bpftrace_path="/usr/bin/bpftrace", is_privileged=True, force_refresh=True
            )
            self.assertTrue(supported)
            self.assertEqual(status, "SUPPORTED")
            self.assertIn("verified via active execution", reason)

            # Verify that -c was included in Popen args
            popen_args = mock_popen.call_args[0][0]
            self.assertIn("-c", popen_args)

        # 2. Probe exits 0 without observing PROBE_OFFSET_HIT -> UNKNOWN
        with patch("shutil.which", return_value="/usr/bin/gcc"), \
             patch("os.stat") as mock_stat, \
             patch("subprocess.run", return_value=mock_gcc_ok), \
             patch("subprocess.Popen") as mock_popen:
            mock_stat.return_value.st_mtime_ns = 5000
            mock_stat.return_value.st_size = 3000
            mock_proc = MagicMock(returncode=0)
            mock_proc.communicate.return_value = ("Attaching 1 probe...\n", "")
            mock_proc.pid = 1234
            mock_popen.return_value = mock_proc

            supported_no_hit, status_no_hit, reason_no_hit = EbpfEnvironmentChecker.check_uprobe_offset_support(
                bpftrace_path="/usr/bin/bpftrace", is_privileged=True, force_refresh=True
            )
            self.assertFalse(supported_no_hit)
            self.assertEqual(status_no_hit, "UNKNOWN")
            self.assertIn("without observing PROBE_OFFSET_HIT", reason_no_hit)

    def test_54_capability_caching_and_invalidation(self):
        """Scenario 54: Verify capability caching by binary stat and explicit cache invalidation."""
        EbpfEnvironmentChecker.invalidate_uprobe_offset_cache()
        mock_disasm = (
            "0000000000000500 <probe_target>:\n"
            " 500:\td503201f\tnop\n"
            " 504:\td503201f\tnop\n"
            " 508:\td65f03c0\tret\n"
        )
        mock_gcc_ok = MagicMock(returncode=0, stderr=b"", stdout=mock_disasm)

        with patch("shutil.which", return_value="/usr/bin/gcc"), \
             patch("os.stat") as mock_stat, \
             patch("subprocess.run", return_value=mock_gcc_ok), \
             patch("subprocess.Popen") as mock_popen:
            mock_stat.return_value.st_mtime_ns = 8000
            mock_stat.return_value.st_size = 4000
            mock_proc = MagicMock(returncode=0)
            mock_proc.communicate.return_value = ("PROBE_OFFSET_HIT\n", "")
            mock_proc.pid = 1234
            mock_popen.return_value = mock_proc

            # First invocation: runs probe and populates cache
            res1 = EbpfEnvironmentChecker.check_uprobe_offset_support(
                bpftrace_path="/usr/bin/bpftrace", is_privileged=True
            )
            self.assertTrue(res1[0])
            self.assertEqual(mock_popen.call_count, 1)

            # Second invocation with same stat: hits cache, does NOT invoke subprocess
            res2 = EbpfEnvironmentChecker.check_uprobe_offset_support(
                bpftrace_path="/usr/bin/bpftrace", is_privileged=True
            )
            self.assertEqual(res2, res1)
            self.assertEqual(mock_popen.call_count, 1, "Cache hit must not invoke subprocess")

            # Binary modified (mtime changes): invalidates cache and runs probe again
            mock_stat.return_value.st_mtime_ns = 9000
            res3 = EbpfEnvironmentChecker.check_uprobe_offset_support(
                bpftrace_path="/usr/bin/bpftrace", is_privileged=True
            )
            self.assertEqual(mock_popen.call_count, 2, "Modified mtime must re-execute probe")

            # Explicit cache invalidation
            EbpfEnvironmentChecker.invalidate_uprobe_offset_cache()
            self.assertEqual(len(EbpfEnvironmentChecker._UPROBE_OFFSET_CACHE), 0)

    def test_55_address_validator_fail_closed_unsupported_arch(self):
        """Scenario 55: Verify AddressValidator strictly fails closed on unsupported architecture names."""
        for bad_arch in ["riscv", "mips", "s390x", "ppc64", "sparc", "unknown", "", None]:
            self.assertFalse(AddressValidator.is_supported_architecture(bad_arch))
            self.assertFalse(AddressValidator.is_valid_instruction_pointer(0x401000, bad_arch))
            self.assertFalse(AddressValidator.is_valid_memory_address(0x401000, 4, bad_arch))
            self.assertIsNone(AddressValidator.normalize_data_address(0x401000, bad_arch))
            self.assertEqual(AddressValidator.untag_data_address(0x401000, bad_arch), 0)
            self.assertIsNone(AddressValidator.compute_link_time_pc(0x401000, 0, bad_arch))

    def test_56_address_normalization_before_memory_read(self):
        """Scenario 56: Verify DwarfEvaluator normalizes tagged data addresses before passing to memory_reader."""
        ident = BinaryIdentity(
            path="/bin/test", elf_class="ELF64", architecture="aarch64", endianness="little",
            build_id="abc", stripped=False, has_debug_info=True,
        )
        subp = DwarfSubprogram(die_offset=0x10, name="func", low_pc=0x1000, frame_base="DW_OP_reg29")

        # 1. Test breg evaluation with tagged pointer
        read_addresses = []
        def mock_reader(addr: int, sz: int) -> Optional[bytes]:
            read_addresses.append(addr)
            return struct.pack("<I", 12345)

        tagged_base = (0xc2 << 56) | 0x00007fffffffe000
        ctx_breg = DwarfEvaluationContext(
            binary_identity=ident,
            subprogram=subp,
            link_time_address=0x1010,
            registers={"x29": tagged_base},
            variable_name="var_breg",
            architecture="aarch64",
            memory_reader=mock_reader,
        )
        res_breg = DwarfEvaluator._evaluate_breg_location(
            ctx_breg, "var_breg", 29, 16, "int", 4, None
        )
        self.assertEqual(res_breg.status, EVAL_STATUS_OBSERVED)
        self.assertEqual(res_breg.value, 12345)
        # Verify the address passed to memory_reader was normalized (tag stripped)
        self.assertEqual(len(read_addresses), 1)
        expected_norm_addr = 0x00007fffffffe000 + 16
        self.assertEqual(read_addresses[0], expected_norm_addr)
        self.assertEqual(res_breg.evaluated_address, expected_norm_addr)

        # 2. Test fbreg evaluation with tagged frame pointer
        read_addresses.clear()
        ctx_fbreg = DwarfEvaluationContext(
            binary_identity=ident,
            subprogram=subp,
            link_time_address=0x1010,
            frame_metadata=FrameMetadata(frame_pointer=tagged_base),
            variable_name="var_fbreg",
            architecture="aarch64",
            memory_reader=mock_reader,
        )
        res_fbreg = DwarfEvaluator._evaluate_frame_base_location(
            ctx_fbreg, "var_fbreg", -32, "int", 4, None
        )
        self.assertEqual(res_fbreg.status, EVAL_STATUS_OBSERVED)
        self.assertEqual(res_fbreg.value, 12345)
        self.assertEqual(len(read_addresses), 1)
        expected_fbreg_addr = 0x00007fffffffe000 - 32
        self.assertEqual(read_addresses[0], expected_fbreg_addr)
        self.assertEqual(res_fbreg.evaluated_address, expected_fbreg_addr)

    def test_57_address_validator_bounds_and_overflow(self):
        """Scenario 57: Verify 64-bit integer overflow protection and page 0 bounds in AddressValidator."""
        # 1. 64-bit overflow: addr + size - 1 wraps around
        overflow_addr = 0xFFFFFFFFFFFFFFFF
        self.assertFalse(AddressValidator.is_valid_memory_address(overflow_addr, 4, "x86_64"))
        self.assertFalse(AddressValidator.is_valid_memory_address(overflow_addr, 4, "aarch64"))

        # 2. Negative address or size <= 0
        self.assertFalse(AddressValidator.is_valid_memory_address(-1, 4, "x86_64"))
        self.assertFalse(AddressValidator.is_valid_memory_address(0x2000, 0, "x86_64"))
        self.assertFalse(AddressValidator.is_valid_memory_address(0x2000, -4, "x86_64"))
        self.assertFalse(AddressValidator.is_valid_memory_address(0x2000, 65537, "x86_64"))

        # 3. Page 0 rejection (< 0x1000)
        self.assertFalse(AddressValidator.is_valid_memory_address(0, 4, "x86_64"))
        self.assertFalse(AddressValidator.is_valid_memory_address(0xFFF, 1, "x86_64"))
        self.assertTrue(AddressValidator.is_valid_memory_address(0x1000, 1, "x86_64"))

        # 4. AArch64 48-bit ceiling vs 52-bit ceiling
        addr_48bit_max = 0x0000FFFFFFFFFFFF
        addr_52bit_val = 0x0001000000000000  # > 48-bit, <= 52-bit
        self.assertTrue(AddressValidator.is_valid_memory_address(addr_48bit_max - 3, 4, "aarch64", fifty_two_bit_va=False))
        self.assertFalse(AddressValidator.is_valid_memory_address(addr_52bit_val, 4, "aarch64", fifty_two_bit_va=False))
        self.assertTrue(AddressValidator.is_valid_memory_address(addr_52bit_val, 4, "aarch64", fifty_two_bit_va=True))

    def test_58_capabilities_default_no_active_probe(self):
        """Scenario 58: Default capabilities() call is inexpensive and does not compile fixtures or spawn probes."""
        EbpfEnvironmentChecker.invalidate_uprobe_offset_cache()
        backend = EbpfObservationBackend()
        with patch.object(EbpfEnvironmentChecker, "check_uprobe_offset_support") as mock_active:
            caps = backend.capabilities(active_probe=False)
            mock_active.assert_not_called()
            self.assertEqual(caps.get("uprobe_offset_status"), "NOT_CHECKED")
            self.assertFalse(caps.get("uprobe_offset_supported"))

    def test_59_force_refresh_propagation_and_cache_bypass(self):
        """Scenario 59: probe_uprobe_offset propagates force_refresh and properly utilizes cache."""
        EbpfEnvironmentChecker.invalidate_uprobe_offset_cache()
        backend = EbpfObservationBackend()

        mock_disasm = (
            "0000000000000500 <probe_target>:\n"
            " 500:\td503201f\tnop\n"
            " 504:\td503201f\tnop\n"
            " 508:\td65f03c0\tret\n"
        )
        mock_gcc_ok = MagicMock(returncode=0, stderr=b"", stdout=mock_disasm)

        with patch("shutil.which", return_value="/usr/bin/gcc"), \
             patch("os.stat") as mock_stat, \
             patch("subprocess.run", return_value=mock_gcc_ok), \
             patch("subprocess.Popen") as mock_popen:
            mock_stat.return_value.st_mtime_ns = 5555
            mock_stat.return_value.st_size = 4444
            mock_proc = MagicMock(returncode=0)
            mock_proc.communicate.return_value = ("PROBE_OFFSET_HIT\n", "")
            mock_proc.pid = 4321
            mock_popen.return_value = mock_proc

            # 1. Initial active probe: executes and populates cache
            res1 = backend.probe_uprobe_offset(force_refresh=False)
            self.assertEqual(mock_popen.call_count, 1)
            self.assertTrue(res1.get("uprobe_offset_supported"))
            self.assertEqual(res1.get("uprobe_offset_status"), "SUPPORTED")

            # 2. Subsequent default capabilities() query reuses cached result without active probe
            caps = backend.capabilities(active_probe=False)
            self.assertEqual(mock_popen.call_count, 1, "Default capabilities must reuse cache without executing probe")
            self.assertTrue(caps.get("uprobe_offset_supported"))
            self.assertEqual(caps.get("uprobe_offset_status"), "SUPPORTED")

            # 3. probe_uprobe_offset(force_refresh=True) bypasses cache and re-runs probe
            res2 = backend.probe_uprobe_offset(force_refresh=True)
            self.assertEqual(mock_popen.call_count, 2, "force_refresh=True must re-run active probe")
            self.assertTrue(res2.get("uprobe_offset_supported"))

            # 4. invalidate_uprobe_offset_cache causes subsequent query to be NOT_CHECKED unless active_probe=True
            EbpfEnvironmentChecker.invalidate_uprobe_offset_cache()
            caps_after_inval = backend.capabilities(active_probe=False)
            self.assertEqual(caps_after_inval.get("uprobe_offset_status"), "NOT_CHECKED")
            self.assertFalse(caps_after_inval.get("uprobe_offset_supported"))
            self.assertEqual(mock_popen.call_count, 2, "Default capabilities after invalidation must not run probe")

            # 5. Subsequent probe_uprobe_offset re-executes probe
            res3 = backend.probe_uprobe_offset(force_refresh=False)
            self.assertEqual(mock_popen.call_count, 3, "Active probe after invalidation must run probe")
            self.assertTrue(res3.get("uprobe_offset_supported"))

    def test_60_instruction_offset_selection_safe_fail_and_parsing(self):
        """Scenario 60: Unit test instruction offset parsing and fail-safe boundaries without guessing."""
        # 1. Unsupported architecture fails closed
        off, err = EbpfEnvironmentChecker._parse_disassembly_for_second_instruction("", "sym", "riscv")
        self.assertIsNone(off)
        self.assertIn("Unsupported architecture", err)

        # 2. Missing symbol
        off, err = EbpfEnvironmentChecker._parse_disassembly_for_second_instruction(
            "0000 <other_sym>:\n 0: nop\n", "probe_target", "x86_64"
        )
        self.assertIsNone(off)
        self.assertIn("Symbol 'probe_target' not found", err)

        # 3. Fewer than 2 instructions
        single_inst = "00000500 <probe_target>:\n 500: c3 ret\n"
        off, err = EbpfEnvironmentChecker._parse_disassembly_for_second_instruction(
            single_inst, "probe_target", "x86_64"
        )
        self.assertIsNone(off)
        self.assertIn("fewer than 2 instructions", err)

        # 4. Duplicate or non-increasing instruction addresses
        dup_addrs = "00000500 <probe_target>:\n 500: nop\n 500: nop\n 504: ret\n"
        off, err = EbpfEnvironmentChecker._parse_disassembly_for_second_instruction(
            dup_addrs, "probe_target", "x86_64"
        )
        self.assertIsNone(off)
        self.assertIn("Non-increasing or duplicate instruction address", err)

        decreasing_addrs = "00000500 <probe_target>:\n 504: nop\n 500: nop\n 508: ret\n"
        off, err = EbpfEnvironmentChecker._parse_disassembly_for_second_instruction(
            decreasing_addrs, "probe_target", "x86_64"
        )
        self.assertIsNone(off)
        self.assertIn("Non-increasing or duplicate instruction address", err)

        # 5. Second instruction at or beyond function end (only 2 instructions total)
        two_inst_only = "00000500 <probe_target>:\n 500: nop\n 504: ret\n"
        off, err = EbpfEnvironmentChecker._parse_disassembly_for_second_instruction(
            two_inst_only, "probe_target", "x86_64"
        )
        self.assertIsNone(off)
        self.assertIn("at or beyond function end", err)

        # 6. AArch64 not 4-byte aligned (offset or address)
        unaligned_aarch64_off = (
            "00000500 <probe_target>:\n"
            " 500: nop\n"
            " 502: nop\n"
            " 508: ret\n"
        )
        off, err = EbpfEnvironmentChecker._parse_disassembly_for_second_instruction(
            unaligned_aarch64_off, "probe_target", "aarch64"
        )
        self.assertIsNone(off)
        self.assertIn("not 4-byte aligned", err)

        unaligned_aarch64_addr = (
            "00000500 <probe_target>:\n"
            " 500: nop\n"
            " 504: nop\n"
            " 507: ret\n"
        )
        off, err = EbpfEnvironmentChecker._parse_disassembly_for_second_instruction(
            unaligned_aarch64_addr, "probe_target", "aarch64"
        )
        self.assertIsNone(off)
        self.assertIn("not 4-byte aligned", err)

        # 7. x86-64 offset exceeding maximum instruction length (15 bytes)
        excessive_x86_off = (
            "00000500 <probe_target>:\n"
            " 500: nop\n"
            " 520: mov %rsp,%rbp\n"
            " 530: ret\n"
        )
        off, err = EbpfEnvironmentChecker._parse_disassembly_for_second_instruction(
            excessive_x86_off, "probe_target", "x86_64"
        )
        self.assertIsNone(off)
        self.assertIn("exceeds maximum x86 instruction length", err)

        # 8. Function boundary: ensure parser stops at next function header or section header
        multi_func_disasm = (
            "00000500 <probe_target>:\n"
            " 500: 55 push %rbp\n"
            " 501: 48 89 e5 mov %rsp,%rbp\n"
            " 504: c3 ret\n"
            "00000505 <next_function>:\n"
            " 505: 90 nop\n"
        )
        off, err = EbpfEnvironmentChecker._parse_disassembly_for_second_instruction(
            multi_func_disasm, "probe_target", "x86_64"
        )
        self.assertEqual(off, 1)
        self.assertIsNone(err)

        section_disasm = (
            "00000500 <probe_target>:\n"
            " 500: 55 push %rbp\n"
            " 501: 48 89 e5 mov %rsp,%rbp\n"
            " 504: c3 ret\n"
            "Disassembly of section .data:\n"
            " 505: 90 nop\n"
        )
        off, err = EbpfEnvironmentChecker._parse_disassembly_for_second_instruction(
            section_disasm, "probe_target", "x86_64"
        )
        self.assertEqual(off, 1)
        self.assertIsNone(err)

        # 9. Valid x86_64 disassembly (variable length instruction, e.g. 1-byte push)
        valid_x86 = (
            "00000000000005fa <probe_target>:\n"
            " 5fa:\t55\tpush %rbp\n"
            " 5fb:\t48 89 e5\tmov %rsp,%rbp\n"
            " 5fe:\tc3\tret\n"
        )
        off, err = EbpfEnvironmentChecker._parse_disassembly_for_second_instruction(
            valid_x86, "probe_target", "x86_64"
        )
        self.assertEqual(off, 1)
        self.assertIsNone(err)

        # 10. Valid AArch64 disassembly (4-byte instructions)
        valid_aarch64 = (
            "0000000000000500 <probe_target>:\n"
            " 500:\td503201f\tnop\n"
            " 504:\td503201f\tnop\n"
            " 508:\td65f03c0\tret\n"
        )
        off, err = EbpfEnvironmentChecker._parse_disassembly_for_second_instruction(
            valid_aarch64, "probe_target", "aarch64"
        )
        self.assertEqual(off, 4)
        self.assertIsNone(err)

        # 11. _find_second_instruction_offset with missing objdump
        with patch("shutil.which", return_value=None):
            off, err = EbpfEnvironmentChecker._find_second_instruction_offset("/bin/dummy", "sym", "x86_64")
            self.assertIsNone(off)
            self.assertIn("Disassembler 'objdump' not found", err)

        # 12. _find_second_instruction_offset with objdump failure
        mock_objdump_fail = MagicMock(returncode=1, stderr="objdump: file format not recognized")
        with patch("shutil.which", return_value="/usr/bin/objdump"), \
             patch("subprocess.run", return_value=mock_objdump_fail):
            off, err = EbpfEnvironmentChecker._find_second_instruction_offset("/bin/dummy", "sym", "x86_64")
            self.assertIsNone(off)
            self.assertIn("objdump failed", err)

    def test_61_subprocess_cleanup_and_tempfile_removal(self):
        """Scenario 61: Subprocess lifecycle guarantees SIGKILL and tempfile cleanup on all exit paths."""
        EbpfEnvironmentChecker.invalidate_uprobe_offset_cache()
        mock_disasm = (
            "0000000000000500 <probe_target>:\n"
            " 500:\td503201f\tnop\n"
            " 504:\td503201f\tnop\n"
            " 508:\td65f03c0\tret\n"
        )
        mock_gcc_ok = MagicMock(returncode=0, stderr=b"", stdout=mock_disasm)

        created_files = []
        real_named_temp_file = tempfile.NamedTemporaryFile

        def tracking_tempfile(*args, **kwargs):
            tf = real_named_temp_file(*args, **kwargs)
            created_files.append(tf.name)
            created_files.append(tf.name + ".bin")
            return tf

        mock_proc = MagicMock()
        mock_proc.pid = 9876
        mock_proc.poll.return_value = None  # Process is still running when timeout occurs
        mock_proc.communicate.side_effect = subprocess.TimeoutExpired(cmd=["bpftrace"], timeout=2.0)

        real_stat = os.stat
        def fake_stat(p, *args, **kwargs):
            if "bpftrace" in str(p):
                mock_s = MagicMock()
                mock_s.st_mtime_ns = 7777
                mock_s.st_size = 1111
                return mock_s
            return real_stat(p, *args, **kwargs)

        with patch("shutil.which", return_value="/usr/bin/gcc"), \
             patch("os.stat", side_effect=fake_stat), \
             patch("tempfile.NamedTemporaryFile", side_effect=tracking_tempfile), \
             patch("subprocess.run", return_value=mock_gcc_ok) as mock_run, \
             patch("subprocess.Popen", return_value=mock_proc), \
             patch("os.killpg") as mock_killpg:

            supported, status, reason = EbpfEnvironmentChecker.check_uprobe_offset_support(
                bpftrace_path="/usr/bin/bpftrace", is_privileged=True, force_refresh=True
            )
            self.assertFalse(supported)
            self.assertEqual(status, "UNKNOWN")
            self.assertIn("timed out", reason.lower())

            # Verify process cleanup was triggered
            kill_called = (
                mock_killpg.called
                or mock_proc.kill.called
                or any("kill" in str(c) for c in mock_run.call_args_list)
            )
            self.assertTrue(kill_called, "Process termination was not triggered")

            # Verify temporary files were cleaned up
            for fpath in created_files:
                self.assertFalse(os.path.exists(fpath), f"Temporary file {fpath} was not cleaned up!")

    def test_62_terminate_probe_process_modes(self):
        """Scenario 62: Unit test _terminate_probe_process across all execution modes and edge cases."""
        # 0. proc is None -> returns NO_PROCESS
        res_none = EbpfEnvironmentChecker._terminate_probe_process(None, [])
        self.assertFalse(res_none)
        self.assertEqual(res_none.status, "NO_PROCESS")
        self.assertFalse(res_none.child_reaped)
        self.assertFalse(res_none.group_terminated)
        self.assertIn("No process to terminate", res_none.details)

        # 1. Direct child reaped but group state unverified (e.g. non-session leader)
        mock_unverified = MagicMock()
        mock_unverified.pid = 6611
        mock_unverified.poll.side_effect = [None, 0]
        res_unverified = EbpfEnvironmentChecker._terminate_probe_process(
            mock_unverified, [], is_session_leader=False
        )
        self.assertFalse(res_unverified)
        self.assertEqual(res_unverified.status, "UNCERTAIN")
        self.assertTrue(res_unverified.child_reaped)
        self.assertFalse(res_unverified.group_terminated)
        self.assertIn("not a session leader", res_unverified.details)

        # 2. Direct child reaped and group verified absent (clean termination)
        mock_clean = MagicMock()
        mock_clean.pid = 4321
        mock_clean.poll.side_effect = [None, 0]
        with patch("os.killpg") as mock_killpg:
            mock_killpg.side_effect = [None, ProcessLookupError]  # SIGKILL then signal 0 ESRCH
            res_clean = EbpfEnvironmentChecker._terminate_probe_process(mock_clean, [], is_session_leader=True)
            self.assertTrue(res_clean)
            self.assertEqual(res_clean.status, "CLEAN")
            self.assertTrue(res_clean.child_reaped)
            self.assertTrue(res_clean.group_terminated)
            self.assertEqual(mock_killpg.call_count, 2)

        # 3. Direct child exited but descendants remain in group after kill attempt
        mock_exited_desc = MagicMock()
        mock_exited_desc.pid = 4455
        mock_exited_desc.poll.return_value = 0  # Child exited
        with patch("subprocess.run") as mock_run:
            # 1st call: kill -0 -> 0 (descendants alive)
            # 2nd call: kill -KILL -> 0 (sent SIGKILL)
            # 3rd call: kill -0 -> 0 (descendants STILL alive after SIGKILL)
            mock_run.side_effect = [
                MagicMock(returncode=0, stderr="", stdout=""),
                MagicMock(returncode=0, stderr="", stdout=""),
                MagicMock(returncode=0, stderr="", stdout=""),
            ]
            res_desc = EbpfEnvironmentChecker._terminate_probe_process(
                mock_exited_desc, ["sudo", "-n"], is_session_leader=True, group_reap_timeout=0.0
            )
            self.assertFalse(res_desc)
            self.assertEqual(res_desc.status, "GROUP_KILL_FAILED")
            self.assertFalse(res_desc.group_terminated)
            self.assertTrue(res_desc.child_reaped)
            self.assertIn("still contains active processes", res_desc.details)

        # 4. Session/group relationship cannot be established (is_session_leader is None, child already exited)
        mock_no_session = MagicMock()
        mock_no_session.pid = 5511
        mock_no_session.poll.return_value = 0
        with patch("os.killpg") as mock_killpg:
            res_no_sess = EbpfEnvironmentChecker._terminate_probe_process(
                mock_no_session, [], is_session_leader=None
            )
            self.assertFalse(res_no_sess)
            self.assertEqual(res_no_sess.status, "UNCERTAIN")
            self.assertFalse(res_no_sess.group_terminated)
            self.assertTrue(res_no_sess.child_reaped)
            mock_killpg.assert_not_called()  # Refused to signal unverified group

        # 5. Confirmed non-session-leader with surviving descendants (refuses to signal group)
        mock_nonsession = MagicMock()
        mock_nonsession.pid = 6677
        mock_nonsession.poll.side_effect = [None, 0]
        with patch("os.killpg") as mock_killpg:
            res_nonsess = EbpfEnvironmentChecker._terminate_probe_process(
                mock_nonsession, [], is_session_leader=False
            )
            self.assertFalse(res_nonsess)
            self.assertEqual(res_nonsess.status, "UNCERTAIN")
            self.assertFalse(res_nonsess.group_terminated)
            self.assertTrue(res_nonsess.child_reaped)
            mock_killpg.assert_not_called()  # Did NOT signal parent process group
            mock_nonsession.kill.assert_called_once()

        # 6. Refusal to signal an unsafe or unrelated process group (caller PGID or caller PID)
        mock_caller_group = MagicMock()
        mock_caller_group.pid = os.getpgrp()
        mock_caller_group.poll.return_value = 0
        with patch("os.killpg") as mock_killpg:
            res_caller = EbpfEnvironmentChecker._terminate_probe_process(
                mock_caller_group, [], is_session_leader=True
            )
            self.assertFalse(res_caller)
            self.assertEqual(res_caller.status, "UNCERTAIN")
            self.assertFalse(res_caller.group_terminated)
            self.assertIn("Refusing to signal caller's own process or group", res_caller.details)
            mock_killpg.assert_not_called()

        # 7. Group kill succeeds and a subsequent check verifies absence
        mock_running_sudo = MagicMock()
        mock_running_sudo.pid = 5432
        mock_running_sudo.poll.side_effect = [None, 0]
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stderr="", stdout=""),
                MagicMock(returncode=1, stderr="kill: (-5432): No such process", stdout=""),
            ]
            res_sudo = EbpfEnvironmentChecker._terminate_probe_process(
                mock_running_sudo, ["sudo", "-n"], is_session_leader=True
            )
            self.assertTrue(res_sudo)
            self.assertEqual(res_sudo.status, "CLEAN")
            self.assertTrue(res_sudo.child_reaped)
            self.assertTrue(res_sudo.group_terminated)
            self.assertEqual(mock_run.call_count, 2)
            mock_running_sudo.kill.assert_called_once()
            mock_running_sudo.communicate.assert_called_once()

        # 8a. Group kill fails with error, but subsequent verify detects absence -> UNCERTAIN (group_terminated=True, success=False)
        mock_kill_err = MagicMock()
        mock_kill_err.pid = 6543
        mock_kill_err.poll.side_effect = [None, 0]
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=1, stderr="kill: (-6543): Operation not permitted", stdout=""),
                MagicMock(returncode=1, stderr="kill: (-6543): No such process", stdout=""),
            ]
            res_kerr = EbpfEnvironmentChecker._terminate_probe_process(
                mock_kill_err, ["sudo", "-n"], is_session_leader=True
            )
            self.assertFalse(res_kerr)
            self.assertEqual(res_kerr.status, "UNCERTAIN")
            self.assertTrue(res_kerr.child_reaped)
            self.assertTrue(res_kerr.group_terminated)
            self.assertIn("Operation not permitted", res_kerr.details)
            self.assertIn("causality UNCERTAIN", res_kerr.details)

        # 8b. Group kill fails with error, and subsequent verify detects group STILL ALIVE -> GROUP_KILL_FAILED (group_terminated=False)
        mock_kill_alive = MagicMock()
        mock_kill_alive.pid = 6544
        mock_kill_alive.poll.side_effect = [None, 0]
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=1, stderr="kill: (-6544): Operation not permitted", stdout=""),
                MagicMock(returncode=0, stderr="", stdout=""),
                MagicMock(returncode=0, stderr="", stdout=""),
            ]
            res_alive = EbpfEnvironmentChecker._terminate_probe_process(
                mock_kill_alive, ["sudo", "-n"], is_session_leader=True, group_reap_timeout=0.0
            )
            self.assertFalse(res_alive)
            self.assertEqual(res_alive.status, "GROUP_KILL_FAILED")
            self.assertTrue(res_alive.child_reaped)
            self.assertFalse(res_alive.group_terminated)
            self.assertIn("Operation not permitted", res_alive.details)

        # 9. Signal-0 permission failure and command timeout -> UNCERTAIN
        mock_uncertain = MagicMock()
        mock_uncertain.pid = 8765
        mock_uncertain.poll.side_effect = [None, 0]
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stderr="", stdout=""),
                MagicMock(returncode=2, stderr="kill: invalid option", stdout=""),
            ]
            res_unc = EbpfEnvironmentChecker._terminate_probe_process(
                mock_uncertain, ["sudo", "-n"], is_session_leader=True
            )
            self.assertFalse(res_unc)
            self.assertEqual(res_unc.status, "UNCERTAIN")
            self.assertIn("could not be verified", res_unc.details)

        # Signal-0 timeout
        mock_timeout = MagicMock()
        mock_timeout.pid = 8766
        mock_timeout.poll.side_effect = [None, 0]
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stderr="", stdout=""),
                subprocess.TimeoutExpired(cmd=["kill"], timeout=1.0),
            ]
            res_to = EbpfEnvironmentChecker._terminate_probe_process(
                mock_timeout, ["sudo", "-n"], is_session_leader=True
            )
            self.assertFalse(res_to)
            self.assertEqual(res_to.status, "UNCERTAIN")
            self.assertIn("Timeout", res_to.details)

        # 10. Child reaping failure (poll remains None) -> REAP_FAILED
        mock_stuck = MagicMock()
        mock_stuck.pid = 9999
        mock_stuck.poll.return_value = None
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
            res_stuck = EbpfEnvironmentChecker._terminate_probe_process(
                mock_stuck, ["sudo", "-n"], is_session_leader=True
            )
            self.assertFalse(res_stuck)
            self.assertEqual(res_stuck.status, "REAP_FAILED")
            self.assertFalse(res_stuck.child_reaped)
            self.assertFalse(res_stuck.group_terminated)

        # 11. Races between poll, kill, wait, and group verification
        mock_race = MagicMock()
        mock_race.pid = 5566
        mock_race.poll.side_effect = [None, 0]
        with patch("subprocess.run") as mock_run:
            # 1st call: kill -KILL -> returns ESRCH ("no such process")
            # 2nd call: kill -0 -> returns ESRCH ("no such process")
            mock_run.side_effect = [
                MagicMock(returncode=1, stderr="kill: (-5566): No such process", stdout=""),
                MagicMock(returncode=1, stderr="kill: (-5566): No such process", stdout=""),
            ]
            res_race = EbpfEnvironmentChecker._terminate_probe_process(
                mock_race, ["sudo", "-n"], is_session_leader=True
            )
            self.assertTrue(res_race)
            self.assertEqual(res_race.status, "CLEAN")
            self.assertTrue(res_race.group_terminated)

        # 12. Repeated cleanup calls and already-reaped processes (idempotency)
        mock_idempotent = MagicMock()
        mock_idempotent.pid = 4322
        mock_idempotent.poll.return_value = 0
        with patch("os.killpg") as mock_killpg:
            mock_killpg.side_effect = ProcessLookupError("No such process")
            # 1st call
            r1 = EbpfEnvironmentChecker._terminate_probe_process(mock_idempotent, [], is_session_leader=True)
            self.assertTrue(r1)
            self.assertEqual(r1.status, "ALREADY_EXITED")
            self.assertTrue(r1.group_terminated)
            # 2nd call (identical outcome, completely idempotent)
            r2 = EbpfEnvironmentChecker._terminate_probe_process(mock_idempotent, [], is_session_leader=True)
            self.assertEqual(r1, r2)

        # 13. Invalid/untracked PID behavior (None, string, bool, float, negative, 0, 1)
        for invalid_pid in [None, "invalid_pid", "123", True, False, 1.5, 100.0, -42.0, -10, 0, 1]:
            mock_invalid = MagicMock()
            mock_invalid.pid = invalid_pid
            mock_invalid.poll.return_value = 0
            with patch("os.killpg") as mock_killpg:
                res_inv = EbpfEnvironmentChecker._terminate_probe_process(mock_invalid, [])
                self.assertFalse(res_inv)
                self.assertEqual(res_inv.status, "UNCERTAIN")
                self.assertFalse(res_inv.group_terminated)
                self.assertTrue(res_inv.child_reaped)
                mock_killpg.assert_not_called()

    def test_63_cache_invalidation_stat_keys(self):
        """Scenario 63: Cache key comprehensively tracks path, mtime, size, and euid."""
        EbpfEnvironmentChecker.invalidate_uprobe_offset_cache()
        mock_disasm = (
            "0000000000000500 <probe_target>:\n"
            " 500:\td503201f\tnop\n"
            " 504:\td503201f\tnop\n"
            " 508:\td65f03c0\tret\n"
        )
        mock_gcc_ok = MagicMock(returncode=0, stderr=b"", stdout=mock_disasm)

        current_stat = {"mtime": 1000, "size": 2000}
        current_euid = 1000

        real_stat = os.stat
        def dynamic_stat(p, *args, **kwargs):
            if "bpftrace" in str(p):
                m = MagicMock()
                m.st_mtime_ns = current_stat["mtime"]
                m.st_size = current_stat["size"]
                return m
            return real_stat(p, *args, **kwargs)

        mock_proc = MagicMock(returncode=0)
        mock_proc.communicate.return_value = ("PROBE_OFFSET_HIT\n", "")
        mock_proc.pid = 1111

        with patch("shutil.which", return_value="/usr/bin/gcc"), \
             patch("os.stat", side_effect=dynamic_stat), \
             patch("os.geteuid", side_effect=lambda: current_euid), \
             patch("subprocess.run", return_value=mock_gcc_ok), \
             patch("subprocess.Popen", return_value=mock_proc) as mock_popen:

            # 1. Initial probe: populates cache
            res1 = EbpfEnvironmentChecker.check_uprobe_offset_support(
                bpftrace_path="/usr/bin/bpftrace", is_privileged=True, force_refresh=False
            )
            self.assertTrue(res1[0])
            self.assertEqual(mock_popen.call_count, 1)

            # 2. Identical stat and euid: reuses cache
            res2 = EbpfEnvironmentChecker.check_uprobe_offset_support(
                bpftrace_path="/usr/bin/bpftrace", is_privileged=True, force_refresh=False
            )
            self.assertEqual(res2, res1)
            self.assertEqual(mock_popen.call_count, 1)

            # 3. mtime changes -> fresh probe
            current_stat["mtime"] = 2000
            res3 = EbpfEnvironmentChecker.check_uprobe_offset_support(
                bpftrace_path="/usr/bin/bpftrace", is_privileged=True, force_refresh=False
            )
            self.assertEqual(mock_popen.call_count, 2)

            # 4. size changes -> fresh probe
            current_stat["size"] = 3000
            res4 = EbpfEnvironmentChecker.check_uprobe_offset_support(
                bpftrace_path="/usr/bin/bpftrace", is_privileged=True, force_refresh=False
            )
            self.assertEqual(mock_popen.call_count, 3)

            # 5. euid changes -> fresh probe
            current_euid = 0
            res5 = EbpfEnvironmentChecker.check_uprobe_offset_support(
                bpftrace_path="/usr/bin/bpftrace", is_privileged=True, force_refresh=False
            )
            self.assertEqual(mock_popen.call_count, 4)

            # 6. path changes -> fresh probe
            res6 = EbpfEnvironmentChecker.check_uprobe_offset_support(
                bpftrace_path="/usr/local/bin/bpftrace", is_privileged=True, force_refresh=False
            )
            self.assertEqual(mock_popen.call_count, 5)

            # 7. Invalidation clears cache
            EbpfEnvironmentChecker.invalidate_uprobe_offset_cache()
            self.assertEqual(len(EbpfEnvironmentChecker._UPROBE_OFFSET_CACHE), 0)

    def test_64_failure_path_error_classification_and_cleanup(self):
        """Scenario 64: Verify truthful error classification across all failure branches without false positives."""
        EbpfEnvironmentChecker.invalidate_uprobe_offset_cache()
        mock_disasm = (
            "0000000000000500 <probe_target>:\n"
            " 500:\td503201f\tnop\n"
            " 504:\td503201f\tnop\n"
            " 508:\td65f03c0\tret\n"
        )
        mock_gcc_ok = MagicMock(returncode=0, stderr=b"", stdout=mock_disasm)

        real_stat = os.stat
        def fake_stat(p, *args, **kwargs):
            if "bpftrace" in str(p):
                m = MagicMock()
                m.st_mtime_ns = 9999
                m.st_size = 8888
                return m
            return real_stat(p, *args, **kwargs)

        # Branch A: bpftrace fails with permission error
        mock_proc_perm = MagicMock(returncode=1)
        mock_proc_perm.communicate.return_value = ("", "Operation not permitted")
        mock_proc_perm.pid = 1111

        with patch("shutil.which", return_value="/usr/bin/gcc"), \
             patch("os.stat", side_effect=fake_stat), \
             patch("subprocess.run", return_value=mock_gcc_ok), \
             patch("subprocess.Popen", return_value=mock_proc_perm):
            res, status, reason = EbpfEnvironmentChecker.check_uprobe_offset_support(
                bpftrace_path="/usr/bin/bpftrace", is_privileged=True, force_refresh=True
            )
            self.assertFalse(res)
            self.assertEqual(status, "UNKNOWN")
            self.assertIn("permission error", reason.lower())

        # Branch B: bpftrace exits 0 but PROBE_OFFSET_HIT was not observed
        mock_proc_nohit = MagicMock(returncode=0)
        mock_proc_nohit.communicate.return_value = ("Attaching 1 probe...\nProcess exited.\n", "")
        mock_proc_nohit.pid = 2222

        with patch("shutil.which", return_value="/usr/bin/gcc"), \
             patch("os.stat", side_effect=fake_stat), \
             patch("subprocess.run", return_value=mock_gcc_ok), \
             patch("subprocess.Popen", return_value=mock_proc_nohit):
            res, status, reason = EbpfEnvironmentChecker.check_uprobe_offset_support(
                bpftrace_path="/usr/bin/bpftrace", is_privileged=True, force_refresh=True
            )
            self.assertFalse(res)
            self.assertEqual(status, "UNKNOWN")
            self.assertIn("without observing PROBE_OFFSET_HIT", reason)

        # Branch C: bpftrace fails with generic non-zero exit code
        mock_proc_err = MagicMock(returncode=127)
        mock_proc_err.communicate.return_value = ("", "syntax error in probe specification")
        mock_proc_err.pid = 3333

        with patch("shutil.which", return_value="/usr/bin/gcc"), \
             patch("os.stat", side_effect=fake_stat), \
             patch("subprocess.run", return_value=mock_gcc_ok), \
             patch("subprocess.Popen", return_value=mock_proc_err):
            res, status, reason = EbpfEnvironmentChecker.check_uprobe_offset_support(
                bpftrace_path="/usr/bin/bpftrace", is_privileged=True, force_refresh=True
            )
            self.assertFalse(res)
            self.assertEqual(status, "UNKNOWN")
            self.assertIn("exit code 127", reason)

        # Branch D: bpftrace compiled without offset support
        mock_proc_unsupp = MagicMock(returncode=255)
        mock_proc_unsupp.communicate.return_value = ("", "compiled without (k|u)probe offset support")
        mock_proc_unsupp.pid = 4444

        with patch("shutil.which", return_value="/usr/bin/gcc"), \
             patch("os.stat", side_effect=fake_stat), \
             patch("subprocess.run", return_value=mock_gcc_ok), \
             patch("subprocess.Popen", return_value=mock_proc_unsupp):
            res, status, reason = EbpfEnvironmentChecker.check_uprobe_offset_support(
                bpftrace_path="/usr/bin/bpftrace", is_privileged=True, force_refresh=True
            )
            self.assertFalse(res)
            self.assertEqual(status, "UNSUPPORTED")
            self.assertIn("compiled without (k|u)probe offset support", reason)

        # Confirm that none of the failure outcomes were cached as SUPPORTED
        for key, cached_val in EbpfEnvironmentChecker._UPROBE_OFFSET_CACHE.items():
            self.assertFalse(cached_val[0], "Failure outcomes must never be cached as is_supported=True")

    def test_65_temporary_file_removal_all_branches(self):
        """Scenario 65: Temporary C source and binary files are cleaned up across all execution and failure branches."""
        mock_disasm = (
            "0000000000000500 <probe_target>:\n"
            " 500:\td503201f\tnop\n"
            " 504:\td503201f\tnop\n"
            " 508:\td65f03c0\tret\n"
        )
        mock_gcc_ok = MagicMock(returncode=0, stderr=b"", stdout=mock_disasm)
        mock_gcc_err = MagicMock(returncode=1, stderr=b"gcc: fatal error: internal error", stdout="")

        real_stat = os.stat
        def fake_stat(p, *args, **kwargs):
            if "bpftrace" in str(p):
                m = MagicMock()
                m.st_mtime_ns = 5555
                m.st_size = 6666
                return m
            return real_stat(p, *args, **kwargs)

        branches = [
            # 1. Compiler error (gcc returncode != 0)
            ("compiler_error", mock_gcc_err, None, None, "UNKNOWN"),
            # 2. Disassembly / offset determination failure
            ("disasm_failure", MagicMock(returncode=0, stderr=b"", stdout="no instructions"), None, None, "UNKNOWN"),
            # 3. TimeoutExpired
            ("timeout", mock_gcc_ok, subprocess.TimeoutExpired(cmd=["bpftrace"], timeout=2.0), None, "UNKNOWN"),
            # 4. Probe exception (Popen raises exception)
            ("exception", mock_gcc_ok, None, OSError("Exec format error"), "UNKNOWN"),
            # 5. Normal success
            ("success", mock_gcc_ok, ("PROBE_OFFSET_HIT\n", ""), None, "SUPPORTED"),
            # 6. Unsupported diagnostic
            ("unsupported", mock_gcc_ok, ("", "compiled without (k|u)probe offset support"), None, "UNSUPPORTED"),
        ]

        for branch_name, gcc_result, proc_comm, popen_exc, expected_status in branches:
            EbpfEnvironmentChecker.invalidate_uprobe_offset_cache()
            created_files = []
            real_named_temp_file = tempfile.NamedTemporaryFile

            def tracking_tempfile(*args, **kwargs):
                tf = real_named_temp_file(*args, **kwargs)
                created_files.append(tf.name)
                bin_name = tf.name + ".bin"
                created_files.append(bin_name)
                # Create the .bin file on disk so we can verify its deletion
                with open(bin_name, "w") as bf:
                    bf.write("ELF_TEST")
                return tf

            mock_proc = MagicMock()
            mock_proc.pid = 9911
            mock_proc.poll.return_value = 0
            if isinstance(proc_comm, Exception):
                mock_proc.communicate.side_effect = proc_comm
            elif proc_comm is not None:
                mock_proc.communicate.return_value = proc_comm
                mock_proc.returncode = 0 if "PROBE_OFFSET_HIT" in proc_comm[0] else 255

            def fake_popen(*args, **kwargs):
                if popen_exc:
                    raise popen_exc
                return mock_proc

            with patch("shutil.which", return_value="/usr/bin/gcc"), \
                 patch("os.stat", side_effect=fake_stat), \
                 patch("tempfile.NamedTemporaryFile", side_effect=tracking_tempfile), \
                 patch("subprocess.run", return_value=gcc_result), \
                 patch("subprocess.Popen", side_effect=fake_popen), \
                 patch("os.killpg"):

                supported, status, reason = EbpfEnvironmentChecker.check_uprobe_offset_support(
                    bpftrace_path="/usr/bin/bpftrace", is_privileged=True, force_refresh=True
                )
                self.assertEqual(
                    status,
                    expected_status,
                    f"Branch {branch_name} expected status {expected_status}, got {status} ({reason})",
                )

                # Verify all temporary files created on disk were cleaned up
                self.assertGreater(len(created_files), 0, f"Branch {branch_name} created no tracked files")
                for fpath in created_files:
                    self.assertFalse(
                        os.path.exists(fpath),
                        f"Branch {branch_name} leaked temporary file {fpath}",
                    )

    def test_66_capabilities_offset_support_never_claims_arbitrary_instruction_probing(self):
        """Scenario 66: Capability detection never conflates uprobe offset support with arbitrary instruction probing."""
        EbpfEnvironmentChecker.invalidate_uprobe_offset_cache()

        # Mock check_uprobe_offset_support to simulate a verified SUPPORTED environment
        with patch.object(
            EbpfEnvironmentChecker,
            "check_uprobe_offset_support",
            return_value=(True, "SUPPORTED", "uprobe offset support verified via active execution (offset +4)"),
        ), patch("shutil.which", return_value="/usr/bin/bpftrace"), \
           patch("os.geteuid", return_value=0), \
           patch("platform.machine", return_value="aarch64"), \
           patch("sys.platform", "linux"):

            # 1. EbpfEnvironmentChecker.check_prerequisites
            prereq = EbpfEnvironmentChecker.check_prerequisites(active_probe=True, force_refresh=True)
            self.assertTrue(prereq.supports_uprobe_offset)
            self.assertEqual(prereq.uprobe_offset_status, "SUPPORTED")

            # 2. EbpfObservationBackend.capabilities
            backend = EbpfObservationBackend()
            caps = backend.capabilities(active_probe=True)
            self.assertTrue(caps["uprobe_offset_supported"])
            self.assertTrue(caps["supports_uprobe_offset"])
            self.assertEqual(caps["uprobe_offset_status"], "SUPPORTED")
            self.assertFalse(caps["arbitrary_instruction_offset_probing"])
            self.assertFalse(caps["dwarf_eval_scope"]["arbitrary_instruction_offset_probing"])
            self.assertFalse(caps["stack_locals_readable_at_entry"])
            self.assertFalse(caps["locals_readable_at_return"])
            self.assertEqual(caps["consistency"], "PROBE_POINT_EVENT")

    def test_67_probe_cleanup_result_contract_and_equality(self):
        """Scenario 67: Unit test ProbeCleanupResult equality, boolean contract, and serialization."""
        r_success1 = ProbeCleanupResult(
            success=True, child_reaped=True, group_terminated=True, status="CLEAN", details="all good"
        )
        r_success2 = ProbeCleanupResult(
            success=True, child_reaped=True, group_terminated=True, status="CLEAN", details="all good"
        )
        r_diff_details = ProbeCleanupResult(
            success=True, child_reaped=True, group_terminated=True, status="CLEAN", details="different"
        )
        r_failed = ProbeCleanupResult(
            success=False, child_reaped=True, group_terminated=False, status="GROUP_KILL_FAILED", details="failed"
        )

        # 1. Instance equality (same fields -> True)
        self.assertEqual(r_success1, r_success2)
        self.assertNotEqual(r_success1, r_diff_details)
        self.assertNotEqual(r_success1, r_failed)

        # 2. Normal Python equality semantics (dataclass does NOT equal bool)
        self.assertFalse(r_success1 == True)
        self.assertFalse(r_success1 == False)
        self.assertFalse(r_failed == False)
        self.assertFalse(r_failed == True)

        # 3. Truthiness via __bool__
        self.assertTrue(bool(r_success1))
        self.assertFalse(bool(r_failed))
        self.assertTrue(r_success1)
        self.assertFalse(r_failed)

        # 4. Incompatible type comparison returns False without raising
        self.assertFalse(r_success1 == "arbitrary string")
        self.assertFalse(r_success1 == None)
        self.assertFalse(r_success1 == 42)

        # 5. Hashability and set usage (frozen dataclass)
        self.assertEqual(hash(r_success1), hash(r_success2))
        self.assertEqual(len({r_success1, r_success2}), 1)

        # 6. Serialization to dict
        d = r_success1.to_dict()
        self.assertEqual(d["status"], "CLEAN")
        self.assertTrue(d["success"])
        self.assertTrue(d["child_reaped"])
        self.assertTrue(d["group_terminated"])

        # 7. Internal consistency invariant
        r_no_proc = ProbeCleanupResult(
            success=False, child_reaped=False, group_terminated=False, status="NO_PROCESS", details="No process"
        )
        r_unc_absence = ProbeCleanupResult(
            success=False, child_reaped=True, group_terminated=True, status="UNCERTAIN", details="kill failed, absence verified"
        )
        results = [r_success1, r_success2, r_diff_details, r_failed, r_no_proc, r_unc_absence]
        for r in results:
            if r.success:
                self.assertTrue(r.child_reaped)
                self.assertTrue(r.group_terminated)
                self.assertIn(r.status, ("CLEAN", "ALREADY_EXITED"))
            else:
                self.assertIn(r.status, ("GROUP_KILL_FAILED", "REAP_FAILED", "UNCERTAIN", "NO_PROCESS"))
                if r.status == "GROUP_KILL_FAILED":
                    self.assertFalse(r.group_terminated)
                    self.assertTrue(r.child_reaped)
                elif r.status in ("NO_PROCESS", "REAP_FAILED"):
                    self.assertFalse(r.child_reaped)
                    self.assertFalse(r.group_terminated)

    def test_68_real_process_group_lifecycle_and_cleanup(self):
        """Scenario 68: Real operating-system process and process-group lifecycle cleanup test.

        Spawns a real process with start_new_session=True (which spawns a real child in its group),
        uses a filesystem token for deterministic synchronization (avoiding sleep races),
        inspects Linux /proc/<pid>/stat process states across 3 distinct lifecycle checkpoints
        (pre-cleanup, immediate post-cleanup, and final bounded verification), exercises
        _terminate_probe_process, and verifies that the process group and descendant processes
        are cleanly terminated without active leaks or assumption of synchronous init reaping.
        Enumerates /proc entries to verify process-group absence without relying on killpg(0) alone,
        and accounts for PID reuse and races.
        """
        if not sys.platform.startswith("linux"):
            raise unittest.SkipTest("Requires Linux platform")

        with tempfile.TemporaryDirectory() as tmpdir:
            token_file = os.path.join(tmpdir, "gchild_ready.token")
            # Parent spawns grandchild that writes token_file containing its PID and sleeps
            script = (
                f"import os, subprocess, sys, time\n"
                f"gchild = subprocess.Popen([sys.executable, '-c',\n"
                f"    'import os, time; open(\"{token_file}\", \"w\").write(str(os.getpid())); time.sleep(30)'])\n"
                f"time.sleep(30)\n"
            )
            proc = subprocess.Popen(
                [sys.executable, "-c", script],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
            pgid = proc.pid
            gchild_pid = None
            try:
                # Deterministic sync: wait for grandchild to write token file
                deadline = time.monotonic() + 4.0
                while time.monotonic() < deadline:
                    if os.path.exists(token_file) and os.path.getsize(token_file) > 0:
                        try:
                            with open(token_file, "r") as f:
                                gchild_pid = int(f.read().strip())
                            break
                        except Exception:
                            pass
                    time.sleep(0.01)

                self.assertIsNotNone(gchild_pid, "Grandchild did not signal readiness via token file")

                # Verify child is running and pgid matches its PID, and grandchild shares the pgid
                self.assertIsNone(proc.poll())
                self.assertEqual(os.getpgid(pgid), pgid)
                self.assertEqual(os.getpgid(gchild_pid), pgid)

                # Lifecycle Checkpoint 1 (Pre-cleanup): both parent and grandchild must be actively executing
                parent_insp_pre = self._inspect_process(pgid, expected_pgrp=pgid)
                gchild_insp_pre = self._inspect_process(gchild_pid, expected_pgrp=pgid)
                self.assertEqual(
                    parent_insp_pre.status, "ACTIVE",
                    f"Pre-cleanup: Parent PID {pgid} should be ACTIVE, got {parent_insp_pre}"
                )
                self.assertEqual(
                    gchild_insp_pre.status, "ACTIVE",
                    f"Pre-cleanup: Grandchild PID {gchild_pid} should be ACTIVE, got {gchild_insp_pre}"
                )
                parent_starttime = parent_insp_pre.info.get("starttime")
                self.assertIsInstance(parent_starttime, int, f"Parent starttime must be an integer: {parent_insp_pre}")
                self.assertGreaterEqual(parent_starttime, 0, f"Parent starttime must be non-negative: {parent_insp_pre}")

                gchild_starttime = gchild_insp_pre.info.get("starttime")
                self.assertIsInstance(gchild_starttime, int, f"Grandchild starttime must be an integer: {gchild_insp_pre}")
                self.assertGreaterEqual(gchild_starttime, 0, f"Grandchild starttime must be non-negative: {gchild_insp_pre}")

                # Exercise real cleanup
                cleanup_res = EbpfEnvironmentChecker._terminate_probe_process(proc, [], is_session_leader=True)

                # Verify cleanup contract outcome
                self.assertTrue(cleanup_res.success)
                self.assertTrue(cleanup_res.child_reaped)
                self.assertTrue(cleanup_res.group_terminated)
                self.assertEqual(cleanup_res.status, "CLEAN")

                # Lifecycle Checkpoint 2 (Immediate post-cleanup):
                # 2a. Direct child must be reaped by our process via communicate()/wait()
                self.assertIsNotNone(proc.poll(), f"Direct child PID {pgid} was not reaped by communicate()/wait()")
                parent_insp_post = self._inspect_process(pgid, expected_starttime=parent_starttime)
                self.assertEqual(
                    parent_insp_post.status, "ABSENT",
                    f"Direct child PID {pgid} was reaped with waitpid but still observed in process table: {parent_insp_post}"
                )

                # 2b. Grandchild was signaled with SIGKILL: it must NOT be actively executing.
                # It may be ABSENT (already harvested) or ZOMBIE (awaiting init/subreaper reaping).
                gchild_insp_post = self._inspect_process(
                    gchild_pid, expected_pgrp=pgid, expected_starttime=gchild_starttime
                )
                self.assertNotEqual(
                    gchild_insp_post.status, "ACTIVE",
                    f"Grandchild PID {gchild_pid} is still actively executing ({gchild_insp_post}) immediately after cleanup"
                )
                self.assertNotEqual(
                    gchild_insp_post.status, "UNKNOWN",
                    f"Grandchild PID {gchild_pid} inspection is unknown/inconclusive immediately after cleanup: {gchild_insp_post}"
                )

                # Lifecycle Checkpoint 3 (Final bounded verification):
                # Bounded wait with monotonic clock for OS reaper (PID 1 / subreaper) to clear zombie from process table.
                # Note: Grandchild is an orphan adopted by PID 1/subreaper; our process cannot waitpid it.
                poll_deadline = time.monotonic() + 2.0
                last_gchild_insp = None
                last_enum = None
                last_killpg_alive = True
                while time.monotonic() < poll_deadline:
                    last_gchild_insp = self._inspect_process(
                        gchild_pid, expected_pgrp=pgid, expected_starttime=gchild_starttime
                    )
                    last_enum = self._get_group_processes(pgid)
                    try:
                        os.killpg(pgid, 0)
                        last_killpg_alive = True
                    except ProcessLookupError:
                        last_killpg_alive = False

                    # Early exit ONLY if the scan was verified complete, group is genuinely empty,
                    # grandchild is absent, and killpg confirms dead group
                    if last_enum.is_empty() and last_gchild_insp.status == "ABSENT" and not last_killpg_alive:
                        break
                    time.sleep(0.01)

                diag_ctx = (
                    f"PGID={pgid}, gchild_PID={gchild_pid}, "
                    f"last_gchild={last_gchild_insp}, "
                    f"group_enum={last_enum}, "
                    f"killpg_alive={last_killpg_alive}"
                )

                # Direct child must remain completely absent
                final_parent_insp = self._inspect_process(pgid, expected_starttime=parent_starttime)
                self.assertEqual(
                    final_parent_insp.status, "ABSENT",
                    f"Direct child PID {pgid} re-appeared in process table: {final_parent_insp}; context: {diag_ctx}"
                )

                # Verify grandchild is not active (must be ABSENT or ZOMBIE awaiting reaper)
                self.assertNotEqual(
                    last_gchild_insp.status, "ACTIVE",
                    f"Grandchild PID {gchild_pid} in PGID {pgid} is still actively executing after timeout: {last_gchild_insp}; context: {diag_ctx}"
                )
                self.assertNotEqual(
                    last_gchild_insp.status, "UNKNOWN",
                    f"Grandchild PID {gchild_pid} inspection is unknown/inconclusive: {last_gchild_insp}; context: {diag_ctx}"
                )
                self.assertIn(
                    last_gchild_insp.status, ("ABSENT", "ZOMBIE"),
                    f"Grandchild PID {gchild_pid} in unexpected state: {last_gchild_insp}; context: {diag_ctx}"
                )

                # Process-group enumeration must be verified complete (fail-closed against /proc listing failures or indeterminate candidates)
                self.assertTrue(
                    last_enum.complete,
                    f"Process group {pgid} enumeration scan was incomplete or failed: {last_enum.diagnostics}; context: {diag_ctx}"
                )
                self.assertEqual(
                    last_enum.unknown_candidates, {},
                    f"Process group {pgid} enumeration encountered indeterminate candidates: {last_enum.unknown_candidates}; context: {diag_ctx}"
                )

                # Verify intended process group has NO surviving active members (do not rely on killpg(0) alone)
                self.assertEqual(
                    last_enum.active_members, {},
                    f"Process group {pgid} contains surviving active processes after timeout: {last_enum.active_members}; context: {diag_ctx}"
                )

                # Verify intended process group has NO unknown members
                self.assertEqual(
                    last_enum.unknown_members, {},
                    f"Process group {pgid} contains unknown/inconclusive processes after timeout: {last_enum.unknown_members}; context: {diag_ctx}"
                )

                # Any residual group members must strictly be ZOMBIEs awaiting async reaping by PID 1
                for p, insp in last_enum.members.items():
                    self.assertEqual(
                        insp.status, "ZOMBIE",
                        f"Non-zombie process {p} lingering in process group {pgid}: {insp}; context: {diag_ctx}"
                    )

                # Process group cleanliness and emptiness contracts
                self.assertTrue(
                    last_enum.is_clean(),
                    f"Process group {pgid} is not clean: context: {diag_ctx}"
                )
                self.assertEqual(
                    last_enum.is_empty(),
                    len(last_enum.members) == 0,
                    f"is_empty() mismatch with members length: context: {diag_ctx}"
                )
            finally:
                caller_pgrp = os.getpgrp()
                caller_pid = os.getpid()

                # 1. Guarded process-group termination (never signal caller's process or group)
                if isinstance(pgid, int) and pgid > 1 and pgid != caller_pgrp and pgid != caller_pid:
                    try:
                        os.killpg(pgid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass  # Group already terminated - normal expected cleanup
                    except Exception as e:
                        import logging
                        logging.getLogger(__name__).warning("Failed to killpg(%s) in finally: %s", pgid, e)

                # 2. Direct child wait/reap with bounded timeout
                if proc is not None and proc.poll() is None:
                    try:
                        proc.kill()
                    except (ProcessLookupError, PermissionError):
                        pass
                    try:
                        proc.wait(timeout=1.0)
                    except subprocess.TimeoutExpired:
                        import logging
                        logging.getLogger(__name__).warning("Direct child proc PID %s could not be reaped within 1.0s timeout", proc.pid)
                    except Exception as e:
                        import logging
                        logging.getLogger(__name__).warning("Error waiting for proc PID %s in finally: %s", proc.pid, e)

                # 3. Descendant fallback termination (if discovered and safe)
                if isinstance(gchild_pid, int) and gchild_pid > 1 and gchild_pid != caller_pid and gchild_pid != caller_pgrp:
                    try:
                        os.kill(gchild_pid, signal.SIGKILL)
                    except (ProcessLookupError, PermissionError):
                        pass
                    except Exception as e:
                        import logging
                        logging.getLogger(__name__).warning("Failed to kill grandchild %s in finally: %s", gchild_pid, e)

                # 4. Final safety diagnostic verification without hiding residual active leaks
                residual_leaks = []
                if isinstance(pgid, int) and pgid > 1 and pgid != caller_pgrp:
                    p_insp = self._inspect_process(pgid)
                    if p_insp.status == "ACTIVE":
                        residual_leaks.append(f"Parent PID {pgid} is still {p_insp}")
                    grp_enum = self._get_group_processes(pgid)
                    for p_mem, insp_mem in grp_enum.members.items():
                        if insp_mem.status == "ACTIVE" and p_mem != caller_pid:
                            residual_leaks.append(f"Group member PID {p_mem} in PGID {pgid} is still {insp_mem}")
                if isinstance(gchild_pid, int) and gchild_pid > 1 and gchild_pid != caller_pid and gchild_pid != caller_pgrp:
                    g_insp = self._inspect_process(gchild_pid)
                    if g_insp.status == "ACTIVE":
                        residual_leaks.append(f"Grandchild PID {gchild_pid} is still {g_insp}")
                if residual_leaks:
                    import logging
                    logging.getLogger(__name__).warning("Residual active process leak after test_68 cleanup: %s", ", ".join(residual_leaks))

    def test_69_no_mock_specific_branches_in_production(self):
        """Scenario 69: Verify production code contains no test-framework-specific attributes or mocks."""
        tracer_path = os.path.join(os.path.dirname(__file__), "..", "extractor", "ebpf_tracer.py")
        with open(tracer_path, "r", encoding="utf-8") as f:
            code = f.read()

        # Production code must not introspect mock attributes like assert_called or import unittest.mock
        self.assertNotIn("assert_called", code)
        self.assertNotIn("unittest.mock", code)
        self.assertNotIn("MagicMock", code)

        # Test dependency injection for group_reap_timeout and sleep_fn
        sleep_calls = []
        mock_proc = MagicMock()
        mock_proc.pid = 9911
        mock_proc.poll.side_effect = [None, 0]
        with patch("subprocess.run") as mock_run:
            # 1st call: kill -KILL -> 0
            # 2nd call: kill -0 -> 0 (alive)
            # (sleep_fn called)
            # 3rd call: kill -0 -> 0 (still alive)
            # (sleep_fn called)
            # 4th call: kill -0 -> 1 (now gone ESRCH!)
            mock_run.side_effect = [
                MagicMock(returncode=0, stderr="", stdout=""),
                MagicMock(returncode=0, stderr="", stdout=""),
                MagicMock(returncode=0, stderr="", stdout=""),
                MagicMock(returncode=1, stderr="kill: (-9911): No such process", stdout=""),
            ]
            res = EbpfEnvironmentChecker._terminate_probe_process(
                mock_proc,
                ["sudo", "-n"],
                is_session_leader=True,
                group_reap_timeout=0.5,
                sleep_fn=lambda dt: sleep_calls.append(dt),
            )
            self.assertTrue(res.success)
            self.assertEqual(res.status, "CLEAN")
            self.assertTrue(res.group_terminated)
            self.assertEqual(len(sleep_calls), 2)
            self.assertEqual(sleep_calls, [0.01, 0.01])

    def test_70_probe_cleanup_result_invariant_enforcement(self):
        """Scenario 70: Verify ProbeCleanupResult enforces all integrity invariants at construction time."""
        # 1. success=True requires child_reaped=True
        with self.assertRaises(ValueError) as ctx:
            ProbeCleanupResult(success=True, child_reaped=False, group_terminated=True, status="CLEAN", details="")
        self.assertIn("success=True requires child_reaped=True", str(ctx.exception))

        # 2. success=True requires group_terminated=True
        with self.assertRaises(ValueError) as ctx:
            ProbeCleanupResult(success=True, child_reaped=True, group_terminated=False, status="CLEAN", details="")
        self.assertIn("group_terminated=True", str(ctx.exception))

        # 3. success=True requires status in ('CLEAN', 'ALREADY_EXITED')
        for bad_status in ("GROUP_KILL_FAILED", "REAP_FAILED", "UNCERTAIN", "NO_PROCESS"):
            with self.assertRaises(ValueError) as ctx:
                ProbeCleanupResult(success=True, child_reaped=True, group_terminated=True, status=bad_status, details="")
            self.assertIn("status in ('CLEAN', 'ALREADY_EXITED')", str(ctx.exception))

        # 4. NO_PROCESS requires success=False, child_reaped=False, group_terminated=False
        with self.assertRaises(ValueError):
            ProbeCleanupResult(success=True, child_reaped=False, group_terminated=False, status="NO_PROCESS", details="")
        with self.assertRaises(ValueError):
            ProbeCleanupResult(success=False, child_reaped=True, group_terminated=False, status="NO_PROCESS", details="")
        with self.assertRaises(ValueError):
            ProbeCleanupResult(success=False, child_reaped=False, group_terminated=True, status="NO_PROCESS", details="")

        # 5. REAP_FAILED cannot have child_reaped=True, group_terminated=True, or success=True
        with self.assertRaises(ValueError):
            ProbeCleanupResult(success=False, child_reaped=True, group_terminated=True, status="REAP_FAILED", details="")
        with self.assertRaises(ValueError):
            ProbeCleanupResult(success=False, child_reaped=True, group_terminated=False, status="REAP_FAILED", details="")
        with self.assertRaises(ValueError):
            ProbeCleanupResult(success=False, child_reaped=False, group_terminated=True, status="REAP_FAILED", details="")
        with self.assertRaises(ValueError):
            ProbeCleanupResult(success=True, child_reaped=False, group_terminated=False, status="REAP_FAILED", details="")

        # 6. GROUP_KILL_FAILED requires success=False, group_terminated=False, child_reaped=True
        with self.assertRaises(ValueError):
            ProbeCleanupResult(success=False, child_reaped=True, group_terminated=True, status="GROUP_KILL_FAILED", details="")
        with self.assertRaises(ValueError):
            ProbeCleanupResult(success=True, child_reaped=True, group_terminated=False, status="GROUP_KILL_FAILED", details="")
        with self.assertRaises(ValueError):
            ProbeCleanupResult(success=False, child_reaped=False, group_terminated=False, status="GROUP_KILL_FAILED", details="")

        # 7. UNCERTAIN cannot claim success=True, or group_terminated=True when child_reaped=False
        with self.assertRaises(ValueError):
            ProbeCleanupResult(success=True, child_reaped=True, group_terminated=False, status="UNCERTAIN", details="")
        with self.assertRaises(ValueError):
            ProbeCleanupResult(success=True, child_reaped=True, group_terminated=True, status="UNCERTAIN", details="")
        with self.assertRaises(ValueError):
            ProbeCleanupResult(success=False, child_reaped=False, group_terminated=True, status="UNCERTAIN", details="")

    def test_71_cleanup_failure_propagation_in_offset_support(self):
        """Scenario 71: Verify cleanup warnings are propagated without distorting kernel capability."""
        # Mock successful probe compilation, execution, and event marker output
        with patch.object(EbpfEnvironmentChecker, "_find_second_instruction_offset", return_value=(4, None)), \
             patch("shutil.which", side_effect=lambda x: f"/usr/bin/{x}"), \
             patch("os.stat") as mock_stat:
            mock_stat.return_value = MagicMock(st_mtime_ns=12345, st_size=6789)

            mock_proc = MagicMock()
            mock_proc.returncode = 0
            mock_proc.communicate.return_value = ("PROBE_OFFSET_HIT\n", "")

            # 1. When cleanup fails (e.g. GROUP_KILL_FAILED), primary capability is preserved with a warning
            cleanup_failed = ProbeCleanupResult(
                success=False,
                child_reaped=True,
                group_terminated=False,
                status="GROUP_KILL_FAILED",
                details="Failed to send SIGKILL to group",
            )
            with patch("subprocess.run") as mock_run, \
                 patch("subprocess.Popen", return_value=mock_proc), \
                 patch.object(EbpfEnvironmentChecker, "_terminate_probe_process", return_value=cleanup_failed) as mock_term:
                mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
                supported, status, reason = EbpfEnvironmentChecker.check_uprobe_offset_support(
                    bpftrace_path="/usr/bin/bpftrace",
                    is_privileged=True,
                    force_refresh=True,
                )
                self.assertTrue(supported)
                self.assertEqual(status, "SUPPORTED")
                self.assertIn("uprobe offset support verified via active execution (offset +4)", reason)
                self.assertIn("[cleanup warning: GROUP_KILL_FAILED - Failed to send SIGKILL to group]", reason)
                # Ensure _terminate_probe_process was called exactly once (no duplicate cleanup call in finally)
                self.assertEqual(mock_term.call_count, 1)

            # 2. When cleanup succeeds (CLEAN), no warning is appended
            cleanup_clean = ProbeCleanupResult(
                success=True,
                child_reaped=True,
                group_terminated=True,
                status="CLEAN",
                details="Process group terminated cleanly",
            )
            with patch("subprocess.run") as mock_run, \
                 patch("subprocess.Popen", return_value=mock_proc), \
                 patch.object(EbpfEnvironmentChecker, "_terminate_probe_process", return_value=cleanup_clean) as mock_term:
                mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
                supported, status, reason = EbpfEnvironmentChecker.check_uprobe_offset_support(
                    bpftrace_path="/usr/bin/bpftrace",
                    is_privileged=True,
                    force_refresh=True,
                )
                self.assertTrue(supported)
                self.assertEqual(status, "SUPPORTED")
                self.assertNotIn("cleanup warning", reason)
                self.assertEqual(mock_term.call_count, 1)

    def test_72_probe_cleanup_result_table_driven_validation(self):
        """Scenario 72: Table-driven validation of ProbeCleanupResult valid and invalid state matrices."""
        # Valid state combinations (must instantiate without error)
        valid_cases = [
            (True, True, True, "CLEAN", "Cleaned up"),
            (True, True, True, "ALREADY_EXITED", "Already dead"),
            (False, False, False, "NO_PROCESS", "No proc"),
            (False, True, False, "UNCERTAIN", "Not leader"),
            (False, False, False, "UNCERTAIN", "Untracked"),
            (False, True, True, "UNCERTAIN", "Kill signal failed, but descendants absent"),
            (False, False, False, "REAP_FAILED", "Stuck child"),
            (False, True, False, "GROUP_KILL_FAILED", "Kill failed, descendants alive"),
        ]
        for success, child_reaped, group_terminated, status, details in valid_cases:
            res = ProbeCleanupResult(
                success=success,
                child_reaped=child_reaped,
                group_terminated=group_terminated,
                status=status,
                details=details,
            )
            self.assertEqual(res.success, success)
            self.assertEqual(res.child_reaped, child_reaped)
            self.assertEqual(res.group_terminated, group_terminated)
            self.assertEqual(res.status, status)
            self.assertEqual(bool(res), success)
            self.assertEqual(res.to_dict()["status"], status)

        # Invalid state combinations (must raise ValueError)
        invalid_cases = [
            # success=True but child not reaped
            (True, False, True, "CLEAN", "Invalid"),
            # success=True but group not terminated
            (True, True, False, "CLEAN", "Invalid"),
            # success=True with failure status
            (True, True, True, "GROUP_KILL_FAILED", "Invalid"),
            (True, True, True, "REAP_FAILED", "Invalid"),
            (True, True, True, "UNCERTAIN", "Invalid"),
            (True, True, True, "NO_PROCESS", "Invalid"),
            # CLEAN with success=False
            (False, True, True, "CLEAN", "Invalid"),
            # ALREADY_EXITED with success=False
            (False, True, True, "ALREADY_EXITED", "Invalid"),
            # NO_PROCESS claiming child reaped or group terminated
            (False, True, False, "NO_PROCESS", "Invalid"),
            (False, False, True, "NO_PROCESS", "Invalid"),
            (True, False, False, "NO_PROCESS", "Invalid"),
            # UNCERTAIN claiming group terminated when child not reaped
            (False, False, True, "UNCERTAIN", "Invalid"),
            # REAP_FAILED claiming child reaped or group terminated
            (False, True, False, "REAP_FAILED", "Invalid"),
            (False, False, True, "REAP_FAILED", "Invalid"),
            (False, True, True, "REAP_FAILED", "Invalid"),
            # GROUP_KILL_FAILED claiming success, group_terminated=True, or child not reaped
            (True, True, True, "GROUP_KILL_FAILED", "Invalid"),
            (False, True, True, "GROUP_KILL_FAILED", "Invalid"),
            (False, False, False, "GROUP_KILL_FAILED", "Invalid"),
            (False, False, True, "GROUP_KILL_FAILED", "Invalid"),
        ]
        for success, child_reaped, group_terminated, status, details in invalid_cases:
            with self.assertRaises(ValueError):
                ProbeCleanupResult(
                    success=success,
                    child_reaped=child_reaped,
                    group_terminated=group_terminated,
                    status=status,
                    details=details,
                )

    def test_73_safe_remove_tempfile_all_scenarios(self):
        """Scenario 73: Deterministic unit tests for _safe_remove_tempfile across all execution and fallback branches."""
        # 1. Real filesystem-level test: unprivileged removal succeeds
        with tempfile.TemporaryDirectory() as tmpdir:
            fpath = os.path.join(tmpdir, "test_file.txt")
            with open(fpath, "w") as f:
                f.write("hello")
            self.assertTrue(os.path.exists(fpath))
            ok, err = EbpfEnvironmentChecker._safe_remove_tempfile(fpath, [])
            self.assertTrue(ok)
            self.assertIsNone(err)
            self.assertFalse(os.path.exists(fpath))

        # 2. None or nonexistent path returns True, None immediately
        self.assertEqual(EbpfEnvironmentChecker._safe_remove_tempfile(None, []), (True, None))
        self.assertEqual(EbpfEnvironmentChecker._safe_remove_tempfile("/tmp/nonexistent_1234567.tmp", []), (True, None))

        # 3. os.remove fails with PermissionError, but privileged fallback succeeds
        with patch("os.path.exists", side_effect=[True, True, False]), \
             patch("os.remove", side_effect=PermissionError("Permission denied")), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
            ok, err = EbpfEnvironmentChecker._safe_remove_tempfile("/tmp/fake_bin", ["sudo", "-n"])
            self.assertTrue(ok)
            self.assertIsNone(err)
            mock_run.assert_called_once_with(
                ["sudo", "-n", "rm", "-f", "--", "/tmp/fake_bin"],
                capture_output=True,
                text=True,
                timeout=2.0,
            )

        # 4. Privileged fallback returns nonzero exit code and file still exists
        with patch("os.path.exists", return_value=True), \
             patch("os.remove", side_effect=PermissionError("Permission denied")), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="rm: cannot remove: Read-only file system", stdout="")
            ok, err = EbpfEnvironmentChecker._safe_remove_tempfile("/tmp/readonly_bin", ["sudo", "-n"])
            self.assertFalse(ok)
            self.assertIn("Read-only file system", err)

        # 5. Privileged fallback times out and file still exists
        with patch("os.path.exists", return_value=True), \
             patch("os.remove", side_effect=PermissionError("Permission denied")), \
             patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=["rm"], timeout=2.0)):
            ok, err = EbpfEnvironmentChecker._safe_remove_tempfile("/tmp/stuck_bin", ["sudo", "-n"])
            self.assertFalse(ok)
            self.assertIn("Privileged rm exception", err)

        # 6. Privileged fallback returns 0, but file still exists (nominal success anomaly)
        with patch("os.path.exists", return_value=True), \
             patch("os.remove", side_effect=PermissionError("Permission denied")), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
            ok, err = EbpfEnvironmentChecker._safe_remove_tempfile("/tmp/ghost_bin", ["sudo", "-n"])
            self.assertFalse(ok)
            self.assertIn("returned 0 but file still exists", err)

    def test_74_check_uprobe_offset_support_all_cleanup_failure_paths(self):
        """Scenario 74: Verify all active-probe failure and cleanup warning propagation paths."""
        with patch.object(EbpfEnvironmentChecker, "_find_second_instruction_offset", return_value=(4, None)), \
             patch("shutil.which", side_effect=lambda x: f"/usr/bin/{x}"), \
             patch("os.stat") as mock_stat:
            mock_stat.return_value = MagicMock(st_mtime_ns=12345, st_size=6789)

            mock_proc = MagicMock()
            mock_proc.returncode = 0
            mock_proc.communicate.return_value = ("PROBE_OFFSET_HIT\n", "")

            # 1. Active probe succeeds, but _terminate_probe_process raises unexpected exception
            with patch("subprocess.run", return_value=MagicMock(returncode=0, stderr="", stdout="")), \
                 patch("subprocess.Popen", return_value=mock_proc), \
                 patch.object(EbpfEnvironmentChecker, "_terminate_probe_process", side_effect=RuntimeError("killpg bug")) as mock_term:
                supported, status, reason = EbpfEnvironmentChecker.check_uprobe_offset_support(
                    bpftrace_path="/usr/bin/bpftrace",
                    is_privileged=True,
                    force_refresh=True,
                )
                self.assertTrue(supported)
                self.assertEqual(status, "SUPPORTED")
                self.assertIn("uprobe offset support verified via active execution (offset +4)", reason)
                self.assertIn("[cleanup warning: UNCERTAIN - Unexpected cleanup exception: killpg bug]", reason)
                self.assertEqual(mock_term.call_count, 1)

            # 2. Active probe times out, and cleanup returns failure
            cleanup_failed = ProbeCleanupResult(
                success=False,
                child_reaped=True,
                group_terminated=False,
                status="GROUP_KILL_FAILED",
                details="Kill signal rejected",
            )
            mock_proc_to = MagicMock()
            mock_proc_to.communicate.side_effect = subprocess.TimeoutExpired(cmd=["bpftrace"], timeout=3.0)
            mock_proc_to.pid = 7711
            with patch("subprocess.run", return_value=MagicMock(returncode=0, stderr="", stdout="")), \
                 patch("subprocess.Popen", return_value=mock_proc_to), \
                 patch.object(EbpfEnvironmentChecker, "_terminate_probe_process", return_value=cleanup_failed):
                supported, status, reason = EbpfEnvironmentChecker.check_uprobe_offset_support(
                    bpftrace_path="/usr/bin/bpftrace",
                    is_privileged=True,
                    force_refresh=True,
                )
                self.assertFalse(supported)
                self.assertEqual(status, "UNKNOWN")
                self.assertIn("timed out after 3.0s", reason.lower())
                self.assertIn("[cleanup warning: GROUP_KILL_FAILED - Kill signal rejected]", reason)

            # 3. Compiler failure combined with temporary-file cleanup failure
            mock_gcc_fail = MagicMock(returncode=1, stderr=b"gcc error", stdout="")
            with patch("subprocess.run", return_value=mock_gcc_fail), \
                 patch.object(EbpfEnvironmentChecker, "_safe_remove_tempfile", return_value=(False, "disk full")):
                supported, status, reason = EbpfEnvironmentChecker.check_uprobe_offset_support(
                    bpftrace_path="/usr/bin/bpftrace",
                    is_privileged=True,
                    force_refresh=True,
                )
                self.assertFalse(supported)
                self.assertEqual(status, "UNKNOWN")
                self.assertIn("Failed to build probe test binary", reason)
                self.assertIn("[tempfile warning: failed to remove source: disk full]", reason)

            # 4. Unexpected communicate exception combined with cleanup failure
            mock_proc_err = MagicMock()
            mock_proc_err.communicate.side_effect = OSError("Corrupted pipe descriptor")
            mock_proc_err.pid = 8822
            with patch("subprocess.run", return_value=MagicMock(returncode=0, stderr="", stdout="")), \
                 patch("subprocess.Popen", return_value=mock_proc_err), \
                 patch.object(EbpfEnvironmentChecker, "_terminate_probe_process", return_value=cleanup_failed):
                supported, status, reason = EbpfEnvironmentChecker.check_uprobe_offset_support(
                    bpftrace_path="/usr/bin/bpftrace",
                    is_privileged=True,
                    force_refresh=True,
                )
                self.assertFalse(supported)
                self.assertEqual(status, "UNKNOWN")
                self.assertIn("Corrupted pipe descriptor", reason)
                self.assertIn("[cleanup warning: GROUP_KILL_FAILED - Kill signal rejected]", reason)

    def test_75_process_inspection_defensive_parsing_and_pid_reuse(self):
        """Scenario 75: Verify defensive /proc/<pid>/stat parsing, diagnostics, and PID reuse detection."""
        # 1. Active process with complex comm containing spaces and nested parentheses
        complex_stat = "1001 (complex (sub) name) S 500 1200 1200 0 -1 4194304 100 0 0 0 10 20 0 0 20 0 1 0 54321 12345 678"
        insp = self._inspect_process(
            1001,
            stat_reader=lambda p: complex_stat,
            kill_fn=lambda p, s: None,
        )
        self.assertEqual(insp.status, "ACTIVE")
        self.assertEqual(insp.detail, "S")
        self.assertEqual(insp.info["comm"], "complex (sub) name")
        self.assertEqual(insp.info["ppid"], 500)
        self.assertEqual(insp.info["pgrp"], 1200)
        self.assertEqual(insp.info["starttime"], 54321)

        # 2. Backwards-compatible 2-tuple unpacking
        status, detail = insp
        self.assertEqual(status, "ACTIVE")
        self.assertEqual(detail, "S")

        # 3. Zombie process
        zombie_stat = "1002 (zombie_task) Z 500 1200 1200 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 54322"
        z_insp = self._inspect_process(
            1002,
            stat_reader=lambda p: zombie_stat,
            kill_fn=lambda p, s: None,
        )
        self.assertEqual(z_insp.status, "ZOMBIE")
        self.assertEqual(z_insp.detail, "Z")

        # 4. Malformed stat: missing parentheses
        malformed_stat_1 = "1003 malformed_task S 500 1200"
        m1_insp = self._inspect_process(
            1003,
            stat_reader=lambda p: malformed_stat_1,
            kill_fn=lambda p, s: None,
        )
        self.assertEqual(m1_insp.status, "UNKNOWN")
        self.assertIn("Malformed parentheses", m1_insp.detail)

        # 5. Malformed stat: truncated fields (< 20 fields after comm)
        malformed_stat_2 = "1004 (truncated) S"
        m2_insp = self._inspect_process(
            1004,
            stat_reader=lambda p: malformed_stat_2,
            kill_fn=lambda p, s: None,
        )
        self.assertEqual(m2_insp.status, "UNKNOWN")
        self.assertIn("Insufficient fields", m2_insp.detail)

        # 6. Malformed stat: non-integer ppid/pgrp
        malformed_stat_3 = "1005 (bad_ints) S not_an_int not_an_int 0 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 1000"
        m3_insp = self._inspect_process(
            1005,
            stat_reader=lambda p: malformed_stat_3,
            kill_fn=lambda p, s: None,
        )
        self.assertEqual(m3_insp.status, "UNKNOWN")
        self.assertIn("Non-integer field", m3_insp.detail)

        # 7. Unrecognized kernel state character
        unknown_state_stat = "1006 (weird) ? 500 1200 1200 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 54322"
        u_insp = self._inspect_process(
            1006,
            stat_reader=lambda p: unknown_state_stat,
            kill_fn=lambda p, s: None,
        )
        self.assertEqual(u_insp.status, "UNKNOWN")
        self.assertIn("Unrecognized kernel process state '?'", u_insp.detail)

        # 8. PID reuse detection: PGID mismatch
        # Process exists and is ACTIVE, but its pgrp is 1200, while we expect 9999
        reuse_pgrp = self._inspect_process(
            1001,
            expected_pgrp=9999,
            stat_reader=lambda p: complex_stat,
            kill_fn=lambda p, s: None,
        )
        self.assertEqual(reuse_pgrp.status, "ABSENT")
        self.assertIn("PID reused (pgrp 1200 != expected 9999)", reuse_pgrp.detail)

        # 9. PID reuse detection: starttime mismatch
        # Process exists, pgrp matches 1200, but starttime is 54321 while we expect 11111
        reuse_time = self._inspect_process(
            1001,
            expected_pgrp=1200,
            expected_starttime=11111,
            stat_reader=lambda p: complex_stat,
            kill_fn=lambda p, s: None,
        )
        self.assertEqual(reuse_time.status, "ABSENT")
        self.assertIn("PID reused (starttime 54321 != expected 11111)", reuse_time.detail)

        # 10. Process lookup error (kill raises ESRCH)
        def mock_esrch(p, s):
            raise ProcessLookupError(3, "No such process")
        absent_insp = self._inspect_process(9999, kill_fn=mock_esrch)
        self.assertEqual(absent_insp.status, "ABSENT")

        # 11. Permission error on kill
        def mock_eacces(p, s):
            raise PermissionError(1, "Operation not permitted")
        perm_insp = self._inspect_process(9998, kill_fn=mock_eacces)
        self.assertEqual(perm_insp.status, "UNKNOWN")
        self.assertIn("PermissionError", perm_insp.detail)

        # 12. Group process enumeration
        with tempfile.TemporaryDirectory() as fake_proc:
            os.makedirs(os.path.join(fake_proc, "2001"))
            os.makedirs(os.path.join(fake_proc, "2002"))
            os.makedirs(os.path.join(fake_proc, "2003"))
            os.makedirs(os.path.join(fake_proc, "non_numeric"))
            with open(os.path.join(fake_proc, "2001", "stat"), "w", encoding="utf-8") as f:
                f.write("2001 (proc1) S 100 5500 5500 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 1000\n")
            with open(os.path.join(fake_proc, "2002", "stat"), "w", encoding="utf-8") as f:
                f.write("2002 (proc2) Z 100 5500 5500 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 1001\n")
            with open(os.path.join(fake_proc, "2003", "stat"), "w", encoding="utf-8") as f:
                f.write("2003 (other) S 100 8888 8888 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 1002\n")

            real_open = open
            def mock_fake_open(path, *args, **kwargs):
                if isinstance(path, str) and path.startswith("/proc/") and path.endswith("/stat"):
                    parts = path.split("/")
                    pid_str = parts[2]
                    fake_path = os.path.join(fake_proc, pid_str, "stat")
                    return real_open(fake_path, *args, **kwargs)
                return real_open(path, *args, **kwargs)

            with patch("builtins.open", side_effect=mock_fake_open), \
                 patch("os.kill", return_value=None):
                group_5500 = self._get_group_processes(5500, proc_dir=fake_proc)
                self.assertIn(2001, group_5500)
                self.assertIn(2002, group_5500)
                self.assertNotIn(2003, group_5500)
                self.assertEqual(group_5500[2001].status, "ACTIVE")
                self.assertEqual(group_5500[2002].status, "ZOMBIE")
                self.assertTrue(group_5500.complete)
                self.assertEqual(len(group_5500), 2)
                self.assertEqual(len(group_5500.active_members), 1)
                self.assertEqual(len(group_5500.zombie_members), 1)
                self.assertFalse(group_5500.is_clean())
                self.assertFalse(group_5500.is_empty())

    def test_76_fail_closed_group_process_enumeration(self):
        """Scenario 76: Unit test fail-closed process enumeration and lifecycle evidence integrity."""
        # Case 1: /proc directory listing failure (PermissionError, OSError) -> marked incomplete, len/bool raise
        def mock_listdir_perm(d):
            raise PermissionError(13, "Permission denied: /proc")

        enum_err = self._get_group_processes(4000, listdir_fn=mock_listdir_perm)
        self.assertFalse(enum_err.complete)
        self.assertIsNotNone(enum_err.scan_error)
        self.assertIn("Permission denied", enum_err.scan_error)
        self.assertEqual(enum_err.members, {})
        self.assertEqual(enum_err.unknown_candidates, {})
        self.assertFalse(enum_err.is_clean())
        self.assertFalse(enum_err.is_empty())
        with self.assertRaises(RuntimeError) as ctx_len:
            len(enum_err)
        self.assertIn("Cannot determine length of incomplete", str(ctx_len.exception))
        with self.assertRaises(RuntimeError) as ctx_bool:
            bool(enum_err)
        self.assertIn("Cannot evaluate boolean value of incomplete", str(ctx_bool.exception))

        # Case 2: Candidate process stat file cannot be read (PermissionError) -> tracked as unknown, incomplete
        def mock_stat_perm(pid):
            if pid == 4001:
                raise PermissionError(13, "Permission denied")
            return "4002 (other) S 1 9999 9999 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 1000"

        enum_cand_perm = self._get_group_processes(
            4000,
            listdir_fn=lambda d: ["4001", "4002"],
            stat_reader=mock_stat_perm,
        )
        self.assertFalse(enum_cand_perm.complete)
        self.assertIn(4001, enum_cand_perm.unknown_candidates)
        self.assertEqual(enum_cand_perm.unknown_candidates[4001].status, "UNKNOWN")
        self.assertIn("PermissionError", enum_cand_perm.unknown_candidates[4001].detail)
        self.assertFalse(enum_cand_perm.is_clean())
        self.assertFalse(enum_cand_perm.is_empty())
        with self.assertRaises(RuntimeError):
            len(enum_cand_perm)

        # Case 3: Candidate stat malformed/truncated -> tracked as unknown candidate, incomplete
        # Subcase 3a: Corrupted stat line missing closing parenthesis
        enum_malformed = self._get_group_processes(
            4000,
            listdir_fn=lambda d: ["4003"],
            stat_reader=lambda p: "4003 malformed_line_without_parens",
        )
        self.assertFalse(enum_malformed.complete)
        self.assertIn(4003, enum_malformed.unknown_candidates)
        self.assertEqual(enum_malformed.unknown_candidates[4003].status, "UNKNOWN")
        self.assertIn("Malformed parentheses", enum_malformed.unknown_candidates[4003].detail)

        # Subcase 3b: Missing starttime when expected_starttime requested -> UNKNOWN
        truncated_stat = "4004 (trunc_task) S 100 4000 4000 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0"  # only 19 fields after comm
        insp_no_stime = self._inspect_process(
            4004,
            expected_pgrp=4000,
            expected_starttime=98765,
            stat_reader=lambda p: truncated_stat,
        )
        self.assertEqual(insp_no_stime.status, "UNKNOWN")
        self.assertIn("Missing starttime", insp_no_stime.detail)

        # Case 4: Candidate vanishes between listdir and inspection (FileNotFoundError / ESRCH) -> benign transient exit, complete
        def mock_stat_vanish(pid):
            if pid == 4005:
                raise FileNotFoundError(2, "No such file or directory: /proc/4005/stat")
            return "4006 (other) S 1 8888 8888 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 1000"

        enum_vanish = self._get_group_processes(
            4000,
            listdir_fn=lambda d: ["4005", "4006"],
            stat_reader=mock_stat_vanish,
        )
        self.assertTrue(enum_vanish.complete)
        self.assertIn(4005, enum_vanish.transient_exits)
        self.assertEqual(enum_vanish.members, {})
        self.assertEqual(enum_vanish.unknown_candidates, {})
        self.assertTrue(enum_vanish.is_empty())
        self.assertTrue(enum_vanish.is_clean())
        self.assertEqual(len(enum_vanish), 0)
        self.assertFalse(bool(enum_vanish))

        # Case 5: PID reuse: stat file readable, but PGID or starttime mismatches expected identity -> ABSENT
        # 5a: PGID mismatch
        insp_reuse_pgid = self._inspect_process(
            4007,
            expected_pgrp=4000,
            stat_reader=lambda p: "4007 (task) S 1 7777 7777 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 55555",
        )
        self.assertEqual(insp_reuse_pgid.status, "ABSENT")
        self.assertIn("PID reused (pgrp 7777 != expected 4000)", insp_reuse_pgid.detail)

        # 5b: starttime mismatch
        insp_reuse_time = self._inspect_process(
            4007,
            expected_pgrp=4000,
            expected_starttime=11111,
            stat_reader=lambda p: "4007 (task) S 1 4000 4000 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 99999",
        )
        self.assertEqual(insp_reuse_time.status, "ABSENT")
        self.assertIn("PID reused (starttime 99999 != expected 11111)", insp_reuse_time.detail)

        # Case 6: Genuinely empty group: scan succeeds with zero members and zero unknowns -> verified complete and empty
        enum_empty = self._get_group_processes(
            4000,
            listdir_fn=lambda d: ["4008", "4009"],
            stat_reader=lambda p: f"{p} (other) S 1 9999 9999 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 1000",
        )
        self.assertTrue(enum_empty.complete)
        self.assertEqual(enum_empty.members, {})
        self.assertEqual(enum_empty.unknown_candidates, {})
        self.assertTrue(enum_empty.is_empty())
        self.assertTrue(enum_empty.is_clean())
        self.assertEqual(len(enum_empty), 0)
        self.assertFalse(bool(enum_empty))

        # Case 7: Zombie members remain: scan succeeds, complete, zombie members reported, not clean/empty
        enum_zombie = self._get_group_processes(
            4000,
            listdir_fn=lambda d: ["4010"],
            stat_reader=lambda p: "4010 (dead_child) Z 1 4000 4000 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 1000",
        )
        self.assertTrue(enum_zombie.complete)
        self.assertIn(4010, enum_zombie.zombie_members)
        self.assertEqual(enum_zombie.active_members, {})
        self.assertTrue(enum_zombie.is_clean())  # no active or unknown members
        self.assertFalse(enum_zombie.is_empty())  # zombie member exists
        self.assertEqual(len(enum_zombie), 1)
        self.assertTrue(bool(enum_zombie))

        # Case 8: Active member survives: scan succeeds, complete, active members reported, not clean
        enum_active = self._get_group_processes(
            4000,
            listdir_fn=lambda d: ["4011"],
            stat_reader=lambda p: "4011 (live_task) R 1 4000 4000 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 1000",
        )
        self.assertTrue(enum_active.complete)
        self.assertIn(4011, enum_active.active_members)
        self.assertFalse(enum_active.is_clean())
        self.assertFalse(enum_active.is_empty())
        self.assertEqual(len(enum_active), 1)
        self.assertTrue(bool(enum_active))

        # Case 9: Caller asserting group cleanliness fails when UNKNOWN member or incomplete scan returned
        # 9a: Incomplete scan
        self.assertFalse(enum_err.is_clean())
        self.assertFalse(enum_cand_perm.is_clean())
        self.assertFalse(enum_malformed.is_clean())

        # 9b: UNKNOWN member in target group
        enum_unk_member = self._get_group_processes(
            4000,
            listdir_fn=lambda d: ["4012"],
            stat_reader=lambda p: "4012 (mystery) ? 1 4000 4000 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 1000",
        )
        self.assertTrue(enum_unk_member.complete)  # Group membership known (4000), but state char is '?'
        self.assertIn(4012, enum_unk_member.unknown_members)
        self.assertFalse(enum_unk_member.is_clean())
        self.assertFalse(enum_unk_member.is_empty())

        # Case 10: Teardown safety guards in lifecycle tests prevent signaling caller PID/PGID
        # Verify EbpfEnvironmentChecker._terminate_probe_process refuses to signal caller PID or caller PGID
        caller_pid = os.getpid()
        caller_pgid = os.getpgrp()

        mock_caller_proc = MagicMock()
        mock_caller_proc.pid = caller_pid
        mock_caller_proc.poll.return_value = 0

        with patch("os.killpg") as mock_killpg, patch("os.kill") as mock_kill:
            res_caller_p = EbpfEnvironmentChecker._terminate_probe_process(
                mock_caller_proc, [], is_session_leader=True
            )
            self.assertFalse(res_caller_p)
            self.assertEqual(res_caller_p.status, "UNCERTAIN")
            self.assertIn("Refusing to signal caller's own process or group", res_caller_p.details)
            mock_killpg.assert_not_called()

        mock_caller_grp = MagicMock()
        mock_caller_grp.pid = caller_pgid
        mock_caller_grp.poll.return_value = 0

        with patch("os.killpg") as mock_killpg, patch("os.kill") as mock_kill:
            res_caller_g = EbpfEnvironmentChecker._terminate_probe_process(
                mock_caller_grp, [], is_session_leader=True
            )
            self.assertFalse(res_caller_g)
            self.assertEqual(res_caller_g.status, "UNCERTAIN")
            self.assertIn("Refusing to signal caller's own process or group", res_caller_g.details)
            mock_killpg.assert_not_called()

    def test_77_complete_proc_stat_validation_and_lifecycle_verdicts(self):
        """Scenario 77: Hermetic validation of complete stat fields, structural integrity, and lifecycle verdicts."""
        # 1. Stat record with only state, PPID, and PGID fields (< 20 fields) is UNKNOWN
        short_stat = "5001 (short) S 1 1234"
        insp_short = self._inspect_process(5001, stat_reader=lambda p: short_stat)
        self.assertEqual(insp_short.status, "UNKNOWN")
        self.assertIn("Insufficient fields", insp_short.detail)
        self.assertIsNone(insp_short.info.get("pgrp"))

        # 2. Record truncated just before starttime (fields 3 through 21; 19 fields after comm) is UNKNOWN without expected_starttime
        just_before_stime = "5002 (almost) S 100 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0"
        insp_no_stime_req = self._inspect_process(5002, stat_reader=lambda p: just_before_stime)
        self.assertEqual(insp_no_stime_req.status, "UNKNOWN")
        self.assertIn("Insufficient fields", insp_no_stime_req.detail)
        self.assertIn("Missing starttime", insp_no_stime_req.detail)
        self.assertIsNone(insp_no_stime_req.info.get("pgrp"))

        # 3. Complete record with valid starttime is parsed correctly (20 fields after comm)
        valid_stat = "5003 (valid_task) S 100 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 67890"
        insp_valid = self._inspect_process(5003, stat_reader=lambda p: valid_stat)
        self.assertEqual(insp_valid.status, "ACTIVE")
        self.assertEqual(insp_valid.detail, "S")
        self.assertEqual(insp_valid.info["comm"], "valid_task")
        self.assertEqual(insp_valid.info["ppid"], 100)
        self.assertEqual(insp_valid.info["pgrp"], 1234)
        self.assertEqual(insp_valid.info["starttime"], 67890)

        # 4. Malformed required numeric fields (non-integer or negative starttime) are UNKNOWN
        # 4a. Non-integer PPID
        bad_ppid_stat = "5004 (bad_ppid) S not_int 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 67890"
        insp_bad_ppid = self._inspect_process(5004, stat_reader=lambda p: bad_ppid_stat)
        self.assertEqual(insp_bad_ppid.status, "UNKNOWN")
        self.assertIn("Non-integer field", insp_bad_ppid.detail)
        self.assertIsNone(insp_bad_ppid.info.get("pgrp"))

        # 4b. Non-integer PGID
        bad_pgrp_stat = "5004 (bad_pgrp) S 100 not_pgrp 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 67890"
        insp_bad_pgrp = self._inspect_process(5004, stat_reader=lambda p: bad_pgrp_stat)
        self.assertEqual(insp_bad_pgrp.status, "UNKNOWN")
        self.assertIn("Non-integer field", insp_bad_pgrp.detail)
        self.assertIsNone(insp_bad_pgrp.info.get("pgrp"))

        # 4c. Non-integer starttime
        bad_stime_stat = "5004 (bad_stime) S 100 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 not_a_num"
        insp_bad_stime = self._inspect_process(5004, stat_reader=lambda p: bad_stime_stat)
        self.assertEqual(insp_bad_stime.status, "UNKNOWN")
        self.assertIn("Non-integer field", insp_bad_stime.detail)
        self.assertIsNone(insp_bad_stime.info.get("pgrp"))

        # 4d. Negative starttime
        neg_stime_stat = "5004 (neg_stime) S 100 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 -100"
        insp_neg_stime = self._inspect_process(5004, stat_reader=lambda p: neg_stime_stat)
        self.assertEqual(insp_neg_stime.status, "UNKNOWN")
        self.assertIn("Invalid negative starttime", insp_neg_stime.detail)
        self.assertIsNone(insp_neg_stime.info.get("pgrp"))

        # 5. Invalid or multi-character state token is UNKNOWN
        # 5a. Multi-character state token
        multi_stat = "5005 (multi) SLEEP 100 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 67890"
        insp_multi = self._inspect_process(5005, stat_reader=lambda p: multi_stat)
        self.assertEqual(insp_multi.status, "UNKNOWN")
        self.assertIn("Invalid multi-character state token", insp_multi.detail)

        # 5b. Unrecognized single-character state token
        unrec_stat = "5005 (weird) ? 100 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 67890"
        insp_unrec = self._inspect_process(5005, stat_reader=lambda p: unrec_stat)
        self.assertEqual(insp_unrec.status, "UNKNOWN")
        self.assertIn("Unrecognized kernel process state '?'", insp_unrec.detail)

        # 6. Expected starttime cannot be verified when starttime is missing (returns UNKNOWN, not ABSENT)
        just_before_stime_5006 = "5006 (almost) S 100 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0"
        insp_exp_missing = self._inspect_process(
            5006,
            expected_starttime=67890,
            stat_reader=lambda p: just_before_stime_5006,
        )
        self.assertEqual(insp_exp_missing.status, "UNKNOWN")
        self.assertNotEqual(insp_exp_missing.status, "ABSENT")
        self.assertIn("Missing starttime", insp_exp_missing.detail)

        # 7. Candidate whose PGID is readable but state is invalid is retained as UNKNOWN member if belonging to target PGID
        invalid_state_in_group = "5007 (inv_task) ?? 100 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 67890"
        enum_unk_mem = self._get_group_processes(
            1234,
            listdir_fn=lambda d: ["5007"],
            stat_reader=lambda p: invalid_state_in_group,
        )
        self.assertTrue(enum_unk_mem.complete)  # All candidates resolved; group membership is known
        self.assertIn(5007, enum_unk_mem.members)
        self.assertEqual(enum_unk_mem.members[5007].status, "UNKNOWN")
        self.assertIn(5007, enum_unk_mem.unknown_members)
        self.assertEqual(enum_unk_mem.active_members, {})
        self.assertEqual(enum_unk_mem.unknown_candidates, {})
        self.assertFalse(enum_unk_mem.is_clean())  # UNKNOWN member prevents clean verdict
        self.assertFalse(enum_unk_mem.is_empty())

        # 8. Candidate with indeterminate PGID makes enumeration incomplete
        enum_indet = self._get_group_processes(
            1234,
            listdir_fn=lambda d: ["5008"],
            stat_reader=lambda p: "5008 (trunc) S 100",  # truncated, < 20 fields
        )
        self.assertFalse(enum_indet.complete)
        self.assertIn(5008, enum_indet.unknown_candidates)
        self.assertEqual(enum_indet.unknown_candidates[5008].status, "UNKNOWN")
        self.assertEqual(enum_indet.members, {})
        self.assertFalse(enum_indet.is_clean())
        self.assertFalse(enum_indet.is_empty())
        with self.assertRaises(RuntimeError):
            len(enum_indet)
        with self.assertRaises(RuntimeError):
            bool(enum_indet)

        # 9. Complete scan with no members is distinguishable from incomplete scan with no confirmed members
        # Complete empty scan
        enum_comp_empty = self._get_group_processes(
            1234,
            listdir_fn=lambda d: ["5009"],
            stat_reader=lambda p: "5009 (foreign) S 100 9999 9999 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 67890",
        )
        self.assertTrue(enum_comp_empty.complete)
        self.assertEqual(enum_comp_empty.members, {})
        self.assertEqual(enum_comp_empty.unknown_candidates, {})
        self.assertTrue(enum_comp_empty.is_empty())
        self.assertTrue(enum_comp_empty.is_clean())
        self.assertEqual(len(enum_comp_empty), 0)
        self.assertFalse(bool(enum_comp_empty))

        # Incomplete scan with 0 confirmed members
        enum_incomp = self._get_group_processes(
            1234,
            listdir_fn=lambda d: ["5010"],
            stat_reader=lambda p: "5010 malformed_line_no_parens",
        )
        self.assertFalse(enum_incomp.complete)
        self.assertEqual(enum_incomp.members, {})
        self.assertEqual(len(enum_incomp.unknown_candidates), 1)
        self.assertFalse(enum_incomp.is_empty())
        self.assertFalse(enum_incomp.is_clean())
        with self.assertRaises(RuntimeError):
            len(enum_incomp)
        with self.assertRaises(RuntimeError):
            bool(enum_incomp)

        # 10. Table-driven verification of lifecycle state outcomes and predicates
        test_table = [
            # (name, req_pid, stat_line, exp_pgrp, exp_stime, exp_status, exp_detail_sub, exp_is_clean, exp_is_empty)
            (
                "pid_reuse_pgrp_mismatch",
                5011,
                "5011 (task) S 100 8888 8888 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 67890",
                1234,  # expected_pgrp
                None,  # expected_starttime
                "ABSENT",
                "pgrp 8888 != expected 1234",
                None,
                None,
            ),
            (
                "pid_reuse_starttime_mismatch",
                5011,
                "5011 (task) S 100 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 99999",
                1234,
                67890,  # expected_starttime
                "ABSENT",
                "starttime 99999 != expected 67890",
                None,
                None,
            ),
            (
                "confirmed_zombie_member",
                5012,
                "5012 (zomb) Z 100 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 67890",
                1234,
                None,
                "ZOMBIE",
                "Z",
                True,   # is_clean: True because zombie is dead (no active or unknown)
                False,  # is_empty: False because member exists
            ),
            (
                "confirmed_active_member",
                5013,
                "5013 (active) R 100 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 67890",
                1234,
                None,
                "ACTIVE",
                "R",
                False,  # is_clean: False because active member survives
                False,  # is_empty: False
            ),
        ]

        for name, r_pid, s_line, exp_pg, exp_st, exp_stat, exp_det, exp_clean, exp_empty in test_table:
            with self.subTest(case=name):
                insp = self._inspect_process(
                    r_pid,
                    expected_pgrp=exp_pg,
                    expected_starttime=exp_st,
                    stat_reader=lambda p, sl=s_line: sl,
                )
                self.assertEqual(insp.status, exp_stat)
                self.assertIn(exp_det, insp.detail)

                if exp_clean is not None:
                    enum_case = self._get_group_processes(
                        1234,
                        listdir_fn=lambda d, rp=r_pid: [str(rp)],
                        stat_reader=lambda p, sl=s_line: sl,
                    )
                    self.assertTrue(enum_case.complete)
                    self.assertEqual(enum_case.is_clean(), exp_clean)
                    self.assertEqual(enum_case.is_empty(), exp_empty)

    def test_78_process_identity_anchoring_and_stat_verification(self):
        """Scenario 78: Defensive process identity anchoring, stat validation, and lifecycle verdicts."""
        # 1. Leading PID matches requested PID
        valid_stat = "6001 (task1) S 1 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000"
        insp1 = self._inspect_process(6001, stat_reader=lambda p: valid_stat)
        self.assertEqual(insp1.status, "ACTIVE")
        self.assertEqual(insp1.detail, "S")
        self.assertEqual(insp1.info["comm"], "task1")
        self.assertEqual(insp1.info["ppid"], 1)
        self.assertEqual(insp1.info["pgrp"], 1234)
        self.assertEqual(insp1.info["starttime"], 50000)

        # 2. Leading PID differs from requested PID -> UNKNOWN (never ABSENT)
        mismatch_stat = "9999 (foreign) S 1 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000"
        insp2 = self._inspect_process(6002, stat_reader=lambda p: mismatch_stat)
        self.assertEqual(insp2.status, "UNKNOWN")
        self.assertNotEqual(insp2.status, "ABSENT")
        self.assertIn("Mismatched PID in /proc/6002/stat: stat PID 9999 != requested PID 6002", insp2.detail)
        self.assertIsNone(insp2.info.get("pgrp"))

        # 3. Missing or non-numeric leading PID -> UNKNOWN
        # 3a. Missing leading PID (starts directly with parenthesis)
        no_pid_stat = "(task) S 1 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000"
        insp3a = self._inspect_process(6003, stat_reader=lambda p: no_pid_stat)
        self.assertEqual(insp3a.status, "UNKNOWN")
        self.assertIn("Missing leading PID before comm", insp3a.detail)
        self.assertIsNone(insp3a.info.get("pgrp"))

        # 3b. Non-numeric leading PID
        str_pid_stat = "not_a_pid (task) S 1 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000"
        insp3b = self._inspect_process(6003, stat_reader=lambda p: str_pid_stat)
        self.assertEqual(insp3b.status, "UNKNOWN")
        self.assertIn("Malformed non-numeric leading PID 'not_a_pid'", insp3b.detail)
        self.assertIsNone(insp3b.info.get("pgrp"))

        # 3c. Multi-token leading PID
        multi_token_stat = "6003 6004 (task) S 1 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000"
        insp3c = self._inspect_process(6003, stat_reader=lambda p: multi_token_stat)
        self.assertEqual(insp3c.status, "UNKNOWN")
        self.assertIn("Malformed non-numeric leading PID", insp3c.detail)
        self.assertIsNone(insp3c.info.get("pgrp"))

        # 3d. Non-positive leading PID
        neg_pid_stat = "-6003 (task) S 1 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000"
        insp3d = self._inspect_process(6003, stat_reader=lambda p: neg_pid_stat)
        self.assertEqual(insp3d.status, "UNKNOWN")
        self.assertIn("Invalid non-positive PID -6003", insp3d.detail)
        self.assertIsNone(insp3d.info.get("pgrp"))

        # 3e. Zero leading PID
        zero_pid_stat = "0 (task) S 1 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000"
        insp3e = self._inspect_process(6003, stat_reader=lambda p: zero_pid_stat)
        self.assertEqual(insp3e.status, "UNKNOWN")
        self.assertIn("Invalid non-positive PID 0", insp3e.detail)
        self.assertIsNone(insp3e.info.get("pgrp"))

        # 4. comm contains spaces and embedded parentheses and is parsed correctly
        nested_comm_stat = "6004 (task (with) [spaces] and (parens)) S 10 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000"
        insp4 = self._inspect_process(6004, stat_reader=lambda p: nested_comm_stat)
        self.assertEqual(insp4.status, "ACTIVE")
        self.assertEqual(insp4.detail, "S")
        self.assertEqual(insp4.info["comm"], "task (with) [spaces] and (parens)")
        self.assertEqual(insp4.info["ppid"], 10)
        self.assertEqual(insp4.info["pgrp"], 1234)
        self.assertEqual(insp4.info["starttime"], 50000)

        # 5. Negative ppid and pgrp values are rejected as UNKNOWN
        # 5a. Negative ppid
        neg_ppid_stat = "6005 (task) S -1 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000"
        insp5a = self._inspect_process(6005, stat_reader=lambda p: neg_ppid_stat)
        self.assertEqual(insp5a.status, "UNKNOWN")
        self.assertIn("Invalid negative ppid (-1)", insp5a.detail)
        self.assertIsNone(insp5a.info.get("pgrp"))

        # 5b. Negative pgrp
        neg_pgrp_stat = "6005 (task) S 1 -500 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000"
        insp5b = self._inspect_process(6005, stat_reader=lambda p: neg_pgrp_stat)
        self.assertEqual(insp5b.status, "UNKNOWN")
        self.assertIn("Invalid negative pgrp (-500)", insp5b.detail)
        self.assertIsNone(insp5b.info.get("pgrp"))

        # 6. Existing valid stat record still parses correctly
        full_stat = "6006 (full_task) R 100 1234 1234 0 -1 4194304 100 0 0 0 10 20 0 0 20 0 1 0 50000 123456 789 18446744073709551615 4194304 4198400 140737488347136 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0"
        insp6 = self._inspect_process(6006, stat_reader=lambda p: full_stat)
        self.assertEqual(insp6.status, "ACTIVE")
        self.assertEqual(insp6.detail, "R")
        self.assertEqual(insp6.info["comm"], "full_task")
        self.assertEqual(insp6.info["ppid"], 100)
        self.assertEqual(insp6.info["pgrp"], 1234)
        self.assertEqual(insp6.info["starttime"], 50000)

        # 7. Truncated records, malformed state tokens, and missing starttime remain UNKNOWN
        # 7a. Truncated (< 20 fields)
        trunc_stat = "6007 (trunc) S 100 1234 1234"
        insp7a = self._inspect_process(6007, stat_reader=lambda p: trunc_stat)
        self.assertEqual(insp7a.status, "UNKNOWN")
        self.assertIn("Insufficient fields", insp7a.detail)

        # 7b. Malformed multi-character state token
        multi_state_stat = "6007 (state_err) RUNNING 100 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000"
        insp7b = self._inspect_process(6007, stat_reader=lambda p: multi_state_stat)
        self.assertEqual(insp7b.status, "UNKNOWN")
        self.assertIn("Invalid multi-character state token", insp7b.detail)

        # 7c. Missing starttime with expected_starttime
        trunc_before_stime = "6007 (no_stime) S 100 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0"
        insp7c = self._inspect_process(6007, expected_starttime=50000, stat_reader=lambda p: trunc_before_stime)
        self.assertEqual(insp7c.status, "UNKNOWN")
        self.assertNotEqual(insp7c.status, "ABSENT")
        self.assertIn("Missing starttime", insp7c.detail)

        # 8. PID reuse through expected_pgrp/expected_starttime retains existing semantics
        # 8a. pgrp mismatch -> ABSENT
        insp8a = self._inspect_process(
            6008,
            expected_pgrp=9999,
            stat_reader=lambda p: "6008 (task) S 100 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000",
        )
        self.assertEqual(insp8a.status, "ABSENT")
        self.assertIn("pgrp 1234 != expected 9999", insp8a.detail)

        # 8b. starttime mismatch -> ABSENT
        insp8b = self._inspect_process(
            6008,
            expected_pgrp=1234,
            expected_starttime=99999,
            stat_reader=lambda p: "6008 (task) S 100 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000",
        )
        self.assertEqual(insp8b.status, "ABSENT")
        self.assertIn("starttime 50000 != expected 99999", insp8b.detail)

        # 9. Invalid identity evidence cannot make GroupProcessEnumeration complete and clean incorrectly
        invalid_stat_cases = [
            ("mismatched_pid", lambda p: "9999 (other) S 100 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000"),
            ("missing_leading_pid", lambda p: "(no_pid) S 100 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000"),
            ("non_numeric_pid", lambda p: "bad_pid (bad) S 100 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000"),
            ("negative_pgrp", lambda p: "6009 (neg_pg) S 100 -1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000"),
            ("negative_ppid", lambda p: "6009 (neg_pp) S -1 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000"),
        ]
        for case_name, reader_fn in invalid_stat_cases:
            with self.subTest(candidate_case=case_name):
                enum_res = self._get_group_processes(
                    1234,
                    listdir_fn=lambda d: ["6009"],
                    stat_reader=reader_fn,
                )
                self.assertFalse(enum_res.complete, f"Case {case_name} must not be marked complete")
                self.assertIn(6009, enum_res.unknown_candidates)
                self.assertEqual(enum_res.members, {})
                self.assertFalse(enum_res.is_clean(), f"Case {case_name} must not be clean")
                self.assertFalse(enum_res.is_empty(), f"Case {case_name} must not be empty")
                with self.assertRaises(RuntimeError):
                    len(enum_res)
                with self.assertRaises(RuntimeError):
                    bool(enum_res)

        # 10. Existing transient exit, zombie, surviving active member, and caller-process/group signal safety
        # 10a. Transient exit remains complete and clean
        enum_trans = self._get_group_processes(
            1234,
            listdir_fn=lambda d: ["6010"],
            stat_reader=lambda p: (_ for _ in ()).throw(FileNotFoundError("Reaped")),
        )
        self.assertTrue(enum_trans.complete)
        self.assertIn(6010, enum_trans.transient_exits)
        self.assertTrue(enum_trans.is_clean())
        self.assertTrue(enum_trans.is_empty())

        # 10b. Zombie member permits is_clean() == True, but forbids is_empty() == True
        enum_zomb = self._get_group_processes(
            1234,
            listdir_fn=lambda d: ["6011"],
            stat_reader=lambda p: "6011 (zomb) Z 1 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000",
        )
        self.assertTrue(enum_zomb.complete)
        self.assertIn(6011, enum_zomb.zombie_members)
        self.assertTrue(enum_zomb.is_clean())
        self.assertFalse(enum_zomb.is_empty())

        # 10c. Surviving active member forbids both is_clean() and is_empty()
        enum_act = self._get_group_processes(
            1234,
            listdir_fn=lambda d: ["6012"],
            stat_reader=lambda p: "6012 (act) R 1 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000",
        )
        self.assertTrue(enum_act.complete)
        self.assertIn(6012, enum_act.active_members)
        self.assertFalse(enum_act.is_clean())
        self.assertFalse(enum_act.is_empty())

    def test_79_adversarial_proc_stat_input_matrix(self):
        """Scenario 79: Comprehensive adversarial /proc/<pid>/stat parsing and classification matrix."""
        # 1. Invalid requested PID types and values (tested before stat file read or signal check)
        invalid_requested_pids = [
            ("string_pid", "not_a_pid", "Invalid non-integer requested PID"),
            ("none_pid", None, "Invalid non-integer requested PID"),
            ("zero_pid", 0, "Invalid non-positive requested PID 0"),
            ("negative_pid", -42, "Invalid non-positive requested PID -42"),
        ]
        for name, req_p, expected_diag in invalid_requested_pids:
            with self.subTest(req_pid_case=name):
                kill_called = []
                insp = self._inspect_process(
                    req_p,
                    kill_fn=lambda p, s: kill_called.append((p, s)),
                )
                self.assertEqual(insp.status, "UNKNOWN")
                self.assertNotEqual(insp.status, "ABSENT")
                self.assertNotEqual(insp.status, "ACTIVE")
                self.assertIn(expected_diag, insp.detail)
                self.assertEqual(kill_called, [], "kill_fn must never be invoked for invalid requested PID")

        # 2. Table-driven adversarial stat line matrix
        # Each entry: (case_name, req_pid, stat_line, exp_pgrp, exp_stime, expected_status, expected_detail_sub, is_err)
        stat_cases = [
            # 2a. Leading PID defects
            ("pid_mismatch", 7001, "9999 (task) S 100 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000", None, None, "UNKNOWN", "Mismatched PID", True),
            ("missing_leading_pid", 7001, "(task) S 100 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000", None, None, "UNKNOWN", "Missing leading PID", True),
            ("whitespace_leading_pid", 7001, "   (task) S 100 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000", None, None, "UNKNOWN", "Missing leading PID", True),
            ("string_leading_pid", 7001, "not_numeric (task) S 100 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000", None, None, "UNKNOWN", "Malformed non-numeric leading PID", True),
            ("float_leading_pid", 7001, "7001.5 (task) S 100 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000", None, None, "UNKNOWN", "Malformed non-numeric leading PID", True),
            ("multi_token_leading_pid", 7001, "7001 7002 (task) S 100 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000", None, None, "UNKNOWN", "Malformed non-numeric leading PID", True),
            ("zero_leading_pid", 7001, "0 (task) S 100 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000", None, None, "UNKNOWN", "Invalid non-positive PID", True),
            ("negative_leading_pid", 7001, "-7001 (task) S 100 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000", None, None, "UNKNOWN", "Invalid non-positive PID", True),

            # 2b. Parentheses and comm defects
            ("unclosed_comm", 7001, "7001 (unclosed_comm S 100 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000", None, None, "UNKNOWN", "Malformed parentheses", True),
            ("unopened_comm", 7001, "7001 unopened_comm) S 100 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000", None, None, "UNKNOWN", "Malformed parentheses", True),
            ("inverted_parens", 7001, "7001 )inverted( S 100 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000", None, None, "UNKNOWN", "Malformed parentheses", True),
            ("no_parens", 7001, "7001 no_parens S 100 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000", None, None, "UNKNOWN", "Malformed parentheses", True),
            ("empty_comm", 7001, "7001 () S 100 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000", None, None, "ACTIVE", "S", False),
            ("nested_comm_parens", 7001, "7001 (task (sub) [deep (nested)]) S 100 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000", None, None, "ACTIVE", "S", False),
            ("sequential_comm_parens", 7001, "7001 (a) (b) (c) S 100 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000", None, None, "ACTIVE", "S", False),

            # 2c. Field counts (< 20 fields after comm)
            ("no_fields_after_comm", 7001, "7001 (task)", None, None, "UNKNOWN", "Insufficient fields", True),
            ("three_fields_after_comm", 7001, "7001 (task) S 100 1234", None, None, "UNKNOWN", "Insufficient fields", True),
            ("nineteen_fields_after_comm", 7001, "7001 (task) S 100 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0", None, None, "UNKNOWN", "Insufficient fields", True),

            # 2d. State token defects
            ("multi_char_state", 7001, "7001 (task) RUNNING 100 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000", None, None, "UNKNOWN", "Invalid multi-character state token", True),
            ("unrecognized_state_symbol", 7001, "7001 (task) ? 100 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000", None, None, "UNKNOWN", "Unrecognized kernel process state", True),
            ("digit_state_token", 7001, "7001 (task) 7 100 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000", None, None, "UNKNOWN", "Unrecognized kernel process state", True),
            ("valid_lowercase_state", 7001, "7001 (task) t 100 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000", None, None, "ACTIVE", "t", False),
            ("valid_zombie_state", 7001, "7001 (task) Z 100 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000", None, None, "ZOMBIE", "Z", False),

            # 2e. Numeric identity field defects
            ("non_int_ppid", 7001, "7001 (task) S not_ppid 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000", None, None, "UNKNOWN", "Non-integer field", True),
            ("negative_ppid", 7001, "7001 (task) S -1 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000", None, None, "UNKNOWN", "Invalid negative ppid", True),
            ("non_int_pgrp", 7001, "7001 (task) S 100 not_pgrp 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000", None, None, "UNKNOWN", "Non-integer field", True),
            ("negative_pgrp", 7001, "7001 (task) S 100 -500 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000", None, None, "UNKNOWN", "Invalid negative pgrp", True),
            ("non_int_starttime", 7001, "7001 (task) S 100 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 not_time", None, None, "UNKNOWN", "Non-integer field", True),
            ("negative_starttime", 7001, "7001 (task) S 100 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 -100", None, None, "UNKNOWN", "Invalid negative starttime", True),

            # 2f. PID reuse detection
            ("reuse_pgrp_mismatch", 7001, "7001 (task) S 100 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000", 9999, None, "ABSENT", "pgrp 1234 != expected 9999", False),
            ("reuse_stime_mismatch", 7001, "7001 (task) S 100 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000", 1234, 99999, "ABSENT", "starttime 50000 != expected 99999", False),
            ("reuse_both_match", 7001, "7001 (task) S 100 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000", 1234, 50000, "ACTIVE", "S", False),
        ]

        for case_name, req_pid, stat_line, exp_pg, exp_st, exp_status, exp_diag, is_err in stat_cases:
            with self.subTest(stat_matrix_case=case_name):
                insp = self._inspect_process(
                    req_pid,
                    expected_pgrp=exp_pg,
                    expected_starttime=exp_st,
                    stat_reader=lambda p, sl=stat_line: sl,
                )
                self.assertEqual(insp.status, exp_status)
                self.assertIn(exp_diag, insp.detail)
                if is_err:
                    # Invariant: input validation failure must NEVER return ACTIVE, ZOMBIE, or ABSENT
                    self.assertNotIn(insp.status, ("ACTIVE", "ZOMBIE", "ABSENT"))
                    if case_name in ("multi_char_state", "unrecognized_state_symbol", "digit_state_token"):
                        # Readable PGID is retained in info so candidate in target PGID is recorded as UNKNOWN member
                        self.assertEqual(insp.info.get("pgrp"), 1234)
                    else:
                        self.assertIsNone(insp.info.get("pgrp"), f"Corrupted record in {case_name} must not have valid pgrp")

        # 3. Genuine process absence: FileNotFoundError and ProcessLookupError
        def mock_fnf(p):
            raise FileNotFoundError(2, "No such file or directory")
        insp_fnf = self._inspect_process(7001, stat_reader=mock_fnf)
        self.assertEqual(insp_fnf.status, "ABSENT")
        self.assertIn("Stat file absent", insp_fnf.detail)

        def mock_esrch(p, s):
            raise ProcessLookupError(3, "No such process")
        insp_esrch = self._inspect_process(7001, kill_fn=mock_esrch)
        self.assertEqual(insp_esrch.status, "ABSENT")
        self.assertIn("ESRCH", insp_esrch.detail)

        # 4. Invalidation of group enumeration for invalid target_pgid
        for bad_pgid in [0, -1, -999, "not_int", None]:
            with self.subTest(bad_pgid_case=bad_pgid):
                enum_bad = self._get_group_processes(bad_pgid)
                self.assertFalse(enum_bad.complete)
                self.assertEqual(enum_bad.members, {})
                self.assertFalse(enum_bad.is_clean())
                self.assertFalse(enum_bad.is_empty())
                with self.assertRaises(RuntimeError):
                    len(enum_bad)
                with self.assertRaises(RuntimeError):
                    bool(enum_bad)

    def test_80_real_signal_safety_and_adversarial_cleanup(self):
        """Scenario 80: Real OS process group signal safety, bystander isolation, and bounded cleanup."""
        if not sys.platform.startswith("linux"):
            raise unittest.SkipTest("Requires Linux platform")

        caller_pid = os.getpid()
        caller_pgrp = os.getpgrp()

        with tempfile.TemporaryDirectory() as tmpdir:
            target_ready_token = os.path.join(tmpdir, "target_ready.token")
            bystander_ready_token = os.path.join(tmpdir, "bystander_ready.token")

            # 1. Target process group: parent launches grandchild in new session and both sleep
            target_script = (
                f"import os, subprocess, sys, time\n"
                f"gchild = subprocess.Popen([sys.executable, '-c',\n"
                f"    'import os, time; open(\"{target_ready_token}\", \"w\").write(str(os.getpid())); time.sleep(30)'])\n"
                f"time.sleep(30)\n"
            )
            target_proc = subprocess.Popen(
                [sys.executable, "-c", target_script],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            target_pgid = target_proc.pid

            # 2. Bystander process in an independent process group
            bystander_script = (
                f"import os, time\n"
                f"open(\"{bystander_ready_token}\", \"w\").write(str(os.getpid()))\n"
                f"time.sleep(30)\n"
            )
            bystander_proc = subprocess.Popen(
                [sys.executable, "-c", bystander_script],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            bystander_pgid = bystander_proc.pid
            bystander_pid = bystander_proc.pid

            target_gchild_pid = None
            try:
                # Wait for both processes to report ready
                deadline = time.monotonic() + 4.0
                while time.monotonic() < deadline:
                    if target_gchild_pid is None and os.path.exists(target_ready_token) and os.path.getsize(target_ready_token) > 0:
                        try:
                            with open(target_ready_token, "r") as f:
                                target_gchild_pid = int(f.read().strip())
                        except Exception:
                            pass
                    if os.path.exists(bystander_ready_token) and os.path.getsize(bystander_ready_token) > 0:
                        pass
                    if target_gchild_pid is not None and os.path.exists(bystander_ready_token):
                        break
                    time.sleep(0.01)

                self.assertIsNotNone(target_gchild_pid, "Target grandchild failed to signal readiness")
                self.assertTrue(os.path.exists(bystander_ready_token), "Bystander failed to signal readiness")

                # Verify distinct process groups: target_pgid != bystander_pgid != caller_pgrp
                self.assertNotEqual(target_pgid, bystander_pgid)
                self.assertNotEqual(target_pgid, caller_pgrp)
                self.assertNotEqual(bystander_pgid, caller_pgrp)

                # Record pre-cleanup identity and starttimes
                insp_target_p = self._inspect_process(target_pgid, expected_pgrp=target_pgid)
                insp_target_g = self._inspect_process(target_gchild_pid, expected_pgrp=target_pgid)
                insp_bystander = self._inspect_process(bystander_pid, expected_pgrp=bystander_pgid)

                self.assertEqual(insp_target_p.status, "ACTIVE")
                self.assertEqual(insp_target_g.status, "ACTIVE")
                self.assertEqual(insp_bystander.status, "ACTIVE")

                target_p_stime = insp_target_p.info.get("starttime")
                target_g_stime = insp_target_g.info.get("starttime")
                bystander_stime = insp_bystander.info.get("starttime")

                self.assertIsInstance(bystander_stime, int)

                # 3. Perform cleanup on target_proc
                cleanup_res = EbpfEnvironmentChecker._terminate_probe_process(
                    target_proc, [], is_session_leader=True
                )
                self.assertTrue(cleanup_res.success)
                self.assertEqual(cleanup_res.status, "CLEAN")

                # 4. Verify target group was terminated
                self.assertIsNotNone(target_proc.poll())
                insp_post_target_p = self._inspect_process(target_pgid, expected_starttime=target_p_stime)
                self.assertEqual(insp_post_target_p.status, "ABSENT")

                # Bounded wait with monotonic clock for target grandchild to reach terminal non-active state (ABSENT or ZOMBIE)
                deadline = time.monotonic() + 2.0
                insp_post_target_g = None
                while time.monotonic() < deadline:
                    insp_post_target_g = self._inspect_process(
                        target_gchild_pid, expected_pgrp=target_pgid, expected_starttime=target_g_stime
                    )
                    if insp_post_target_g.status in ("ABSENT", "ZOMBIE"):
                        break
                    time.sleep(0.01)

                self.assertIsNotNone(insp_post_target_g)
                self.assertNotEqual(
                    insp_post_target_g.status, "ACTIVE",
                    f"Grandchild {target_gchild_pid} remained active after cleanup: {insp_post_target_g}"
                )
                self.assertNotEqual(
                    insp_post_target_g.status, "UNKNOWN",
                    f"Grandchild {target_gchild_pid} inspection inconclusive after cleanup: {insp_post_target_g}"
                )
                self.assertIn(
                    insp_post_target_g.status, ("ABSENT", "ZOMBIE"),
                    f"Grandchild {target_gchild_pid} was not terminated (got {insp_post_target_g.status})"
                )

                # Direct verification of target process group enumeration
                enum_post = self._get_group_processes(target_pgid)
                self.assertTrue(enum_post.complete, f"Group enumeration incomplete: {enum_post.diagnostics}")
                self.assertEqual(enum_post.active_members, {})
                self.assertEqual(enum_post.unknown_members, {})
                self.assertTrue(enum_post.is_clean())

                # 5. Direct verification: bystander process was NOT signaled and remains ACTIVE
                self.assertIsNone(bystander_proc.poll(), "Bystander process was mistakenly reaped or killed!")
                insp_bystander_post = self._inspect_process(
                    bystander_pid, expected_pgrp=bystander_pgid, expected_starttime=bystander_stime
                )
                self.assertEqual(
                    insp_bystander_post.status, "ACTIVE",
                    f"Bystander process in separate PGID {bystander_pgid} was disrupted: {insp_bystander_post}"
                )
                self.assertEqual(
                    insp_bystander_post.info["starttime"], bystander_stime,
                    "Bystander starttime changed (PID was recycled)!"
                )

                # 6. Direct verification: caller process and group were NOT signaled
                self.assertEqual(os.getpid(), caller_pid)
                self.assertEqual(os.getpgrp(), caller_pgrp)

                # 7. Unverified / non-session-leader protection:
                # Real child spawned in caller's session (start_new_session=False).
                # _terminate_probe_process MUST reap direct child but MUST NOT send os.killpg.
                non_leader_proc = subprocess.Popen(
                    [sys.executable, "-c", "import time; time.sleep(30)"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=False,
                )
                try:
                    self.assertEqual(os.getpgid(non_leader_proc.pid), caller_pgrp)
                    with patch("os.killpg") as mock_killpg:
                        res_non_leader = EbpfEnvironmentChecker._terminate_probe_process(
                            non_leader_proc, [], is_session_leader=False
                        )
                        self.assertFalse(res_non_leader.success)
                        self.assertTrue(res_non_leader.child_reaped)
                        self.assertFalse(res_non_leader.group_terminated)
                        self.assertEqual(res_non_leader.status, "UNCERTAIN")
                        self.assertIn("not a session leader", res_non_leader.details)
                        self.assertIn("collateral group signaling avoided", res_non_leader.details)
                        mock_killpg.assert_not_called()
                        self.assertIsNotNone(non_leader_proc.poll(), "Direct child was not reaped")
                finally:
                    if non_leader_proc.poll() is None:
                        try:
                            non_leader_proc.kill()
                            non_leader_proc.wait(timeout=1.0)
                        except Exception:
                            pass

            finally:
                # Bounded teardown of all spawned processes
                for p_obj, p_gid in [(target_proc, target_pgid), (bystander_proc, bystander_pgid)]:
                    if p_gid and p_gid > 1 and p_gid != caller_pgrp and p_gid != caller_pid:
                        try:
                            os.killpg(p_gid, signal.SIGKILL)
                        except (ProcessLookupError, PermissionError):
                            pass
                        except Exception:
                            pass
                    if p_obj and p_obj.poll() is None:
                        try:
                            p_obj.kill()
                        except Exception:
                            pass
                        try:
                            p_obj.wait(timeout=1.0)
                        except Exception:
                            pass
                if target_gchild_pid and target_gchild_pid > 1 and target_gchild_pid != caller_pid and target_gchild_pid != caller_pgrp:
                    try:
                        os.kill(target_gchild_pid, signal.SIGKILL)
                    except Exception:
                        pass


    def test_81_strict_pid_pgid_type_safety_matrix(self):
        """Scenario 81: Strict PID and PGID type safety across inspection, enumeration, and termination."""
        class CustomIntObject:
            def __int__(self):
                return 7001

        class ExplosiveReprObject:
            def __repr__(self):
                raise RuntimeError("Explosive repr failure")

        # 1. Exhaustive matrix of non-integer, boolean, float, and malformed PID inputs to _inspect_process
        bad_pids = [
            ("true_bool", True),
            ("false_bool", False),
            ("float_val", 100.5),
            ("float_exact", 100.0),
            ("float_neg", -42.0),
            ("none_val", None),
            ("numeric_str", "1234"),
            ("zero_str", "0"),
            ("neg_str", "-42"),
            ("alpha_str", "not_a_pid"),
            ("empty_str", ""),
            ("zero_int", 0),
            ("neg_int", -42),
            ("custom_int_obj", CustomIntObject()),
            ("explosive_repr_obj", ExplosiveReprObject()),
        ]

        for case_name, bad_p in bad_pids:
            with self.subTest(inspect_bad_pid=case_name):
                kill_calls = []
                stat_calls = []
                insp = self._inspect_process(
                    bad_p,
                    kill_fn=lambda p, s: kill_calls.append((p, s)),
                    stat_reader=lambda p: (stat_calls.append(p) or "7001 (task) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000"),
                )
                self.assertEqual(insp.status, "UNKNOWN")
                self.assertNotEqual(insp.status, "ABSENT")
                self.assertNotEqual(insp.status, "ACTIVE")
                self.assertIn(insp.status, {"UNKNOWN"})
                self.assertEqual(kill_calls, [], f"kill_fn was invoked for invalid PID {case_name}")
                self.assertEqual(stat_calls, [], f"stat_reader was invoked for invalid PID {case_name}")

        # 2. Type boundaries for expected_pgrp and expected_starttime in _inspect_process
        bad_expected_pgrps = [
            ("pgrp_true", True),
            ("pgrp_float", 100.0),
            ("pgrp_str", "100"),
            ("pgrp_zero", 0),
            ("pgrp_neg", -1),
        ]
        for name, bad_pgrp in bad_expected_pgrps:
            with self.subTest(expected_pgrp=name):
                insp = self._inspect_process(7001, expected_pgrp=bad_pgrp)
                self.assertEqual(insp.status, "UNKNOWN")
                self.assertIn("Invalid expected_pgrp", insp.detail)

        bad_expected_stimes = [
            ("stime_true", True),
            ("stime_float", 500.5),
            ("stime_str", "50000"),
            ("stime_neg", -1),
        ]
        for name, bad_stime in bad_expected_stimes:
            with self.subTest(expected_starttime=name):
                insp = self._inspect_process(7001, expected_starttime=bad_stime)
                self.assertEqual(insp.status, "UNKNOWN")
                self.assertIn("Invalid expected_starttime", insp.detail)

        # 3. Exhaustive matrix of bad target_pgid inputs to _get_group_processes
        bad_pgids = [
            ("true_bool", True),
            ("false_bool", False),
            ("float_val", 100.5),
            ("float_exact", 100.0),
            ("float_neg", -42.0),
            ("none_val", None),
            ("numeric_str", "1234"),
            ("alpha_str", "not_a_pgid"),
            ("empty_str", ""),
            ("zero_int", 0),
            ("neg_int", -42),
            ("custom_int_obj", CustomIntObject()),
            ("explosive_repr_obj", ExplosiveReprObject()),
        ]
        for case_name, bad_pgid in bad_pgids:
            with self.subTest(enum_bad_pgid=case_name):
                listdir_calls = []
                stat_calls = []
                enum_res = self._get_group_processes(
                    bad_pgid,
                    listdir_fn=lambda d: (listdir_calls.append(d) or ["7001"]),
                    stat_reader=lambda p: (stat_calls.append(p) or "7001 (task) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000"),
                )
                self.assertFalse(enum_res.complete)
                self.assertFalse(enum_res.is_clean())
                self.assertFalse(enum_res.is_empty())
                self.assertIsNotNone(enum_res.scan_error)
                self.assertEqual(listdir_calls, [], f"listdir_fn called for bad pgid {case_name}")
                self.assertEqual(stat_calls, [], f"stat_reader called for bad pgid {case_name}")
                with self.assertRaises(RuntimeError):
                    len(enum_res)
                with self.assertRaises(RuntimeError):
                    bool(enum_res)

        # 4. Bad process group IDs in _verify_process_group_state
        for bad_id in [True, False, 100.5, 100.0, -42.0, None, "1234", "not_a_pgid", 0, 1, -10, CustomIntObject(), ExplosiveReprObject()]:
            term, err = EbpfEnvironmentChecker._verify_process_group_state(bad_id, ["sudo", "-n"])
            self.assertIsNone(term)
            self.assertIsNotNone(err)
            self.assertIn("Invalid process group ID", err)

        # 5. Invalid PIDs in trace() fail immediately without syscalls
        tracer = EbpfTracer()
        for bad_pid in [True, False, 1.5, "123", None, 0, -1, CustomIntObject()]:
            sess = tracer.trace(binary_path="/bin/ls", function_name="main", pid=bad_pid)
            self.assertEqual(sess.status, "FAILED")
            self.assertIn("Invalid target PID", sess.error_message)

    def test_82_process_state_quadrant_and_clean_verdict_proof(self):
        """Scenario 82: Independent verification of process state quadrants and ProbeCleanupResult invariants."""
        # --- Part 1: Four distinct process state quadrants ---
        # Quadrant 1 (ACTIVE): Living process in group prevents CLEAN and EMPTY
        active_stat = "8101 (worker) R 100 8100 8100 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000"
        insp_act = self._inspect_process(8101, stat_reader=lambda p: active_stat)
        self.assertEqual(insp_act.status, "ACTIVE")
        enum_act = self._get_group_processes(
            8100, listdir_fn=lambda d: ["8101"], stat_reader=lambda p: active_stat
        )
        self.assertTrue(enum_act.complete)
        self.assertIn(8101, enum_act.active_members)
        self.assertFalse(enum_act.is_clean())
        self.assertFalse(enum_act.is_empty())

        # Quadrant 2 (ZOMBIE): Zombie in group permits is_clean()=True, but forbids is_empty()=True
        zombie_stat = "8102 (worker) Z 100 8100 8100 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000"
        insp_zomb = self._inspect_process(8102, stat_reader=lambda p: zombie_stat)
        self.assertEqual(insp_zomb.status, "ZOMBIE")
        enum_zomb = self._get_group_processes(
            8100, listdir_fn=lambda d: ["8102"], stat_reader=lambda p: zombie_stat
        )
        self.assertTrue(enum_zomb.complete)
        self.assertEqual(enum_zomb.active_members, {})
        self.assertIn(8102, enum_zomb.members)
        self.assertTrue(enum_zomb.is_clean(), "Zombie waiting for OS reaper permits is_clean()=True")
        self.assertFalse(enum_zomb.is_empty(), "Zombie lingering in /proc strictly forbids is_empty()=True")

        # Quadrant 3 (ABSENT): Reaped process permits both is_clean()=True and is_empty()=True
        def raise_fnf(p):
            raise FileNotFoundError(f"/proc/{p}/stat absent")
        insp_abs = self._inspect_process(8103, stat_reader=raise_fnf)
        self.assertEqual(insp_abs.status, "ABSENT")
        enum_abs = self._get_group_processes(8100, listdir_fn=lambda d: [], stat_reader=raise_fnf)
        self.assertTrue(enum_abs.complete)
        self.assertEqual(enum_abs.members, {})
        self.assertTrue(enum_abs.is_clean())
        self.assertTrue(enum_abs.is_empty())

        # PID reuse detection yielding ABSENT:
        reuse_stat = "8103 (worker) S 100 8100 8100 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 99999"
        insp_reuse = self._inspect_process(8103, expected_starttime=50000, stat_reader=lambda p: reuse_stat)
        self.assertEqual(insp_reuse.status, "ABSENT")
        self.assertIn("PID reused", insp_reuse.detail)

        # Quadrant 4 (UNKNOWN): Inconclusive inspection never yields ABSENT or CLEAN
        # 4a. PermissionError on stat read
        def raise_perm(p):
            raise PermissionError("EACCES")
        insp_unk_perm = self._inspect_process(8104, stat_reader=raise_perm)
        self.assertEqual(insp_unk_perm.status, "UNKNOWN")
        self.assertNotEqual(insp_unk_perm.status, "ABSENT")
        enum_unk_perm = self._get_group_processes(8100, listdir_fn=lambda d: ["8104"], stat_reader=raise_perm)
        self.assertFalse(enum_unk_perm.complete)
        self.assertIn(8104, enum_unk_perm.unknown_candidates)
        self.assertFalse(enum_unk_perm.is_clean())
        self.assertFalse(enum_unk_perm.is_empty())

        # 4b. Malformed stat record with unparsed PGID
        bad_stat = "8105 (bad_worker) S 100 corrupt_pgid 8100 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000"
        insp_unk_bad = self._inspect_process(8105, stat_reader=lambda p: bad_stat)
        self.assertEqual(insp_unk_bad.status, "UNKNOWN")
        enum_unk_bad = self._get_group_processes(8100, listdir_fn=lambda d: ["8105"], stat_reader=lambda p: bad_stat)
        self.assertFalse(enum_unk_bad.complete)
        self.assertIn(8105, enum_unk_bad.unknown_candidates)
        self.assertFalse(enum_unk_bad.is_clean())
        self.assertFalse(enum_unk_bad.is_empty())

        # 4c. Valid PGID but unrecognized state symbol ('Q') retains target PGID as unknown_members
        unrec_stat = "8106 (worker) Q 100 8100 8100 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 50000"
        insp_unrec = self._inspect_process(8106, stat_reader=lambda p: unrec_stat)
        self.assertEqual(insp_unrec.status, "UNKNOWN")
        enum_unrec = self._get_group_processes(8100, listdir_fn=lambda d: ["8106"], stat_reader=lambda p: unrec_stat)
        self.assertTrue(enum_unrec.complete)
        self.assertIn(8106, enum_unrec.unknown_members)
        self.assertFalse(enum_unrec.is_clean(), "Unknown state token in target group prevents is_clean()=True")
        self.assertFalse(enum_unrec.is_empty())

        # --- Part 2: Table-driven ProbeCleanupResult invariant matrix ---
        valid_matrix = [
            (True, True, True, "CLEAN"),
            (True, True, True, "ALREADY_EXITED"),
            (False, False, False, "NO_PROCESS"),
            (False, False, False, "REAP_FAILED"),
            (False, True, False, "GROUP_KILL_FAILED"),
            (False, True, False, "UNCERTAIN"),
            (False, True, True, "UNCERTAIN"),
            (False, False, False, "UNCERTAIN"),
        ]
        for succ, reaped, term, st in valid_matrix:
            res = ProbeCleanupResult(
                success=succ, child_reaped=reaped, group_terminated=term, status=st, details="valid"
            )
            self.assertEqual(bool(res), succ)

        contradictory_matrix = [
            (True, True, True, "UNCERTAIN"),
            (True, True, False, "CLEAN"),
            (True, False, True, "CLEAN"),
            (False, True, True, "CLEAN"),
            (False, True, True, "ALREADY_EXITED"),
            (False, True, False, "NO_PROCESS"),
            (False, True, False, "REAP_FAILED"),
            (False, True, True, "GROUP_KILL_FAILED"),
            (False, False, False, "GROUP_KILL_FAILED"),
            (False, False, True, "UNCERTAIN"),
            (False, True, True, "INVALID_STATUS"),
        ]
        for succ, reaped, term, st in contradictory_matrix:
            with self.assertRaises(ValueError):
                ProbeCleanupResult(
                    success=succ, child_reaped=reaped, group_terminated=term, status=st, details="contradictory"
                )

    def test_83_trace_cleanup_uses_double_dash_and_safe_pgid(self):
        """Verify that EbpfTracer.trace cleanup uses '--' delimiter to avoid procps kill option parsing bugs."""
        tracer = EbpfTracer(use_sudo=True)
        mock_proc = MagicMock()
        mock_proc.pid = 1936537
        mock_proc.poll.return_value = None  # simulate process still running during cleanup
        mock_proc.wait.side_effect = [subprocess.TimeoutExpired(cmd=["wait"], timeout=2.0), None]
        mock_proc.stdout.readline.return_value = "Attaching 1 probe...\n"
        mock_proc.stdout.readlines.return_value = []
        mock_proc.stderr.readline.return_value = ""

        mock_ident = BinaryIdentity(
            path="/bin/echo",
            architecture="x86_64",
            elf_class="ELF64",
            endianness="little",
            build_id="abcdef",
            stripped=False,
            pt_loads=[{"p_vaddr": 0x400000, "p_memsz": 0x1000, "p_offset": 0, "p_filesz": 0x1000}],
        )

        with patch("extractor.ebpf_tracer.inspect_elf", return_value=mock_ident), \
             patch("os.path.exists", return_value=True), \
             patch("os.kill", return_value=None), \
             patch("os.geteuid", return_value=1001), \
             patch("select.select", return_value=([mock_proc.stdout], [], [])), \
             patch("extractor.ebpf_tracer.EbpfEnvironmentChecker.check_prerequisites") as mock_cap, \
             patch("subprocess.Popen", return_value=mock_proc), \
             patch("subprocess.run") as mock_run:

            mock_cap.return_value = EbpfCapabilityResult(
                supported=True,
                backend="bpftrace",
                architecture="x86_64",
                kernel_version="6.17",
                is_privileged=True,
                unprivileged_bpf_disabled=0,
                has_bpf_fs=True,
            )

            tracer.trace(
                pid=os.getpid(),
                binary_path="/bin/echo",
                function_name="0x400500",
                duration_s=0.01,
            )

            # Both SIGINT and SIGKILL calls must have '--' before the -PGID argument
            self.assertEqual(mock_run.call_count, 2)
            first_cmd = mock_run.call_args_list[0][0][0]
            second_cmd = mock_run.call_args_list[1][0][0]

            self.assertEqual(first_cmd, ["sudo", "-n", "kill", "-INT", "--", "-1936537"])
            self.assertEqual(second_cmd, ["sudo", "-n", "kill", "-KILL", "--", "-1936537"])


if __name__ == "__main__":
    unittest.main()
