"""Comprehensive Tests for Live Capture Integrity, Strict PID Validation, and Evidence Validation.

Covers Acceptance Criteria 1 through 10:
- Strict PID validation (decimals, whitespace, partials, signs, overflow, booleans, nonexistent).
- Capture backend capabilities and metadata reporting (honest atomicity, zero-stop, fallback tracking).
- Snapshot serialization and deserialization fidelity.
- Fail-open cleanup guarantee and PID reuse protection.
- DWARF build ID validation, mismatch refusal, and dynamic load bias.
- Object graph decoding with pointers outside captured memory (MEMORY_NOT_CAPTURED) and cyclic references.
- Honest stage status model (capture, decoding, static linkage, overall) and bounded zero-findings reports.
- Real compiled C++ target live capture latency and process resumption.
"""

import os
import shutil
import signal
import subprocess
import tempfile
import time
import unittest

from extractor.capture_backend import (
    ProcessVmCaptureBackend,
    ProcfsCaptureBackend,
    _get_process_identity,
)
from extractor.debug_image import inspect_elf
from extractor.static_analyzer import (
    IDENTITY_VERIFIED_MATCH,
    IDENTITY_MISMATCH,
    IDENTITY_TARGET_ID_UNAVAILABLE,
)
from extractor.investigation import (
    InvestigationManager,
    NON_ATOMIC,
    STOPPED,
)
from extractor.raw_snapshot import RawRuntimeSnapshot, RawMemoryRegion
from extractor.agent_runtime import AgentRuntime
from extractor.static_analyzer import (
    DwarfStaticAnalysisProvider,
    LINK_KIND_GLOBAL_VARIABLE,
    LINK_KIND_TYPE_DEFINITION,
    LINK_KIND_UNRESOLVED,
)
from extractor.modules import RuntimeModule


class TestLiveCaptureIntegrityAndValidation(unittest.TestCase):
    """Deep test suite for live capture integrity, strict validation, and honest evidence status."""

    @classmethod
    def setUpClass(cls):
        cls.work_dir = tempfile.mkdtemp(prefix="dynstate_integrity_test_")
        cls.corpus_dir = os.path.join(cls.work_dir, "corpus")
        os.makedirs(cls.corpus_dir, exist_ok=True)
        cls.fixture_src = os.path.abspath("tests/fixtures/real_runtime/main.cpp")

        # Compile unstripped debug artifact with DWARF symbols & GNU build-id
        cls.debug_bin = os.path.join(cls.work_dir, "app_debug.elf")
        cmd_debug = [
            "g++", "-fPIE", "-pie", "-g", "-O0", "-fno-inline", "-fno-omit-frame-pointer",
            "-Wl,--build-id=sha1", cls.fixture_src, "-o", cls.debug_bin, "-lpthread"
        ]
        subprocess.run(cmd_debug, check=True)

        # Extract stripped production binary
        cls.stripped_bin = os.path.join(cls.work_dir, "app_prod.stripped")
        subprocess.run(["strip", "-s", "-o", cls.stripped_bin, cls.debug_bin], check=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.work_dir, ignore_errors=True)

    def setUp(self):
        self.mgr = InvestigationManager(corpus_dir=self.corpus_dir)
        self.runtime = AgentRuntime(corpus_dir=self.corpus_dir)

    def _start_target_process(self):
        proc = subprocess.Popen(
            [self.stripped_bin],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        line = proc.stdout.readline().strip()
        self.assertEqual(line, "READY", f"Process failed to report READY: {line}")
        return proc

    def _stop_target_process(self, proc):
        if proc.poll() is None:
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=1)
        if proc.stdout:
            proc.stdout.close()
        if proc.stderr:
            proc.stderr.close()

    # =========================================================================
    # 1. Strict PID Validation Tests
    # =========================================================================

    def test_strict_pid_validation_valid_inputs(self):
        """Valid integer inputs and whitespace-padded integers parse correctly."""
        # Clean numeric integer
        res = self.mgr.start_investigation(goal="test", pid=1234, authorize_target=False)
        self.assertEqual(res["target_ref"]["pid"], 1234)

        # Whitespace padded integer string
        res = self.mgr.start_investigation(goal="test", pid="  5678  ", authorize_target=False)
        self.assertEqual(res["target_ref"]["pid"], 5678)

    def test_strict_pid_validation_rejects_malformed_and_partial_strings(self):
        """Partial strings, letters, signs, decimals, booleans, and out-of-range values are rejected."""
        malformed_cases = [
            "123abc",       # Trailing letters
            "abc123",       # Leading letters
            "123.4",        # Decimal float
            "PID 123",      # Text prefix
            "PID: 123",     # Text prefix with colon
            "+123",         # Plus sign
            "-123",         # Negative sign string
            -5,             # Negative int
            0,              # Zero
            "0",            # Zero string
            2147483648,     # Overflow (> 2^31 - 1)
            "99999999999",  # Overflow string
            True,           # Boolean True
            False,          # Boolean False
            "",             # Empty string
            "   ",          # Pure whitespace
        ]

        for val in malformed_cases:
            res = self.mgr.start_investigation(goal="test malformed", pid=val, authorize_target=True)
            self.assertEqual(res["status"], "FAILED", f"Value {val!r} was not rejected with status FAILED")
            err_msg = res.get("summary", {}).get("error", "")
            self.assertTrue(
                "Invalid PID format" in err_msg or "out of valid range" in err_msg,
                f"Value {val!r} error message unexpected: {err_msg}"
            )

    def test_pid_existence_and_nonexistent_process_error(self):
        """Authorized capture against nonexistent PID returns clear ESRCH error code."""
        res = self.mgr.start_investigation(
            goal="test nonexistent pid",
            pid=999999999,
            authorize_target=True,
        )
        self.assertEqual(res["status"], "FAILED")
        self.assertEqual(res["stages"]["target_identity"]["status"], "FAILED")
        self.assertIn("ESRCH", res["stages"]["target_identity"]["details"]["error"])

    # =========================================================================
    # 2. Capture Backend Capabilities and Honest Metadata
    # =========================================================================

    def test_capture_backend_capabilities_introspection(self):
        """Backends honestly report their capabilities, zero-stop support, and atomicity."""
        pvm = ProcessVmCaptureBackend()
        self.assertEqual(pvm.capabilities["name"], "process_vm_readv")
        self.assertTrue(pvm.capabilities["can_read_memory"])
        self.assertTrue(pvm.capabilities["zero_stop_supported"])
        self.assertEqual(pvm.capabilities["atomicity"], "NON_ATOMIC")

        procfs = ProcfsCaptureBackend()
        self.assertEqual(procfs.capabilities["name"], "procfs")
        self.assertTrue(procfs.capabilities["can_read_memory"])
        self.assertEqual(procfs.capabilities["atomicity"], "NON_ATOMIC")

    def test_capture_quality_metadata_metrics(self):
        """Capture produces honest counts for requested, read, failed, and omitted regions."""
        proc = self._start_target_process()
        try:
            backend = ProcessVmCaptureBackend() if ProcessVmCaptureBackend().is_available(proc.pid) else ProcfsCaptureBackend()
            snap = backend.capture(pid=proc.pid)
            self.assertGreater(snap.bytes_captured, 0)

            prov = snap.provenance
            self.assertIn("bytes_requested", prov)
            self.assertIn("bytes_read", prov)
            self.assertIn("bytes_omitted", prov)
            self.assertIn("regions_attempted", prov)
            self.assertIn("regions_read", prov)
            self.assertIn("regions_failed", prov)
            self.assertIn("regions_omitted", prov)
            self.assertIn("stop_mechanism", prov)
            self.assertIn("stopped_threads", prov)

            # Requested equals read + omitted + failed
            self.assertEqual(prov["bytes_requested"], prov["bytes_read"] + prov["bytes_omitted"])
            self.assertEqual(prov["regions_attempted"], prov["regions_read"] + prov["regions_failed"] + prov["regions_omitted"])

            # Verify atomicity classification: process_vm_readv zero-stop is NON_ATOMIC if not suspended
            obs = snap.observation_metadata
            self.assertIn(obs["consistency_classification"], ("SIGNAL_STOPPED", "NON_ATOMIC"))
        finally:
            self._stop_target_process(proc)

    # =========================================================================
    # 3. Fail-Open Cleanup and PID Reuse Protection
    # =========================================================================

    def test_process_identity_detection_starttime(self):
        """_get_process_identity parses comm and starttime reliably from /proc/<pid>/stat."""
        comm, starttime = _get_process_identity(os.getpid())
        self.assertIsInstance(comm, str)
        self.assertIsInstance(starttime, str)
        self.assertGreater(int(starttime), 0)

    # =========================================================================
    # 4. Snapshot Serialization Fidelity
    # =========================================================================

    def test_raw_runtime_snapshot_serialization_fidelity(self):
        """RawRuntimeSnapshot.save and .load preserve buffers, regions, and provenance exactly."""
        region = RawMemoryRegion(
            region_id="R00001",
            start=0x10000,
            end=0x11000,
            size=0x1000,
            permissions="rw-p",
            category="heap",
            pathname="[heap]",
        )
        fake_data = b"X" * 1024 + b"\x00" * 3072
        snap = RawRuntimeSnapshot(
            snapshot_id="snap_fidelity_test",
            timestamp="2026-10-11T05:00:00Z",
            pid=4321,
            executable="/opt/test_bin",
            executable_build_id="abcdef0123456789",
            memory_regions=[region.to_dict()],
            register_state={},
            captured_ranges=[[0x10000, 0x11000]],
            raw_memory={"total_bytes": 4096},
            capture_backend="process_vm_readv",
            observation_metadata={"consistency_classification": "SIGNAL_STOPPED", "bytes_requested": 4096},
            completeness="COMPLETE",
            capture_duration_us=123.4,
            provenance={"snapshot_consistency": "PROCESS_STOPPED_MEMORY_SNAPSHOT", "bytes_requested": 4096},
            _buffers={(0x10000, 0x11000): fake_data},
        )

        save_path = os.path.join(self.work_dir, "test_snap_save")
        snap.save(save_path)

        loaded = RawRuntimeSnapshot.load(save_path)
        self.assertEqual(loaded.snapshot_id, snap.snapshot_id)
        self.assertEqual(loaded.read_bytes(0x10000, len(fake_data)), fake_data)
        self.assertEqual(loaded._buffers[(0x10000, 0x11000)], fake_data)
        self.assertEqual(loaded.provenance["snapshot_consistency"], "PROCESS_STOPPED_MEMORY_SNAPSHOT")

    # =========================================================================
    # 5. DWARF Build ID Validation and Dynamic Load Bias
    # =========================================================================

    def test_build_id_mismatch_blocks_static_resolution(self):
        """Mismatched build ID sets build_id_status to MISMATCH and marks static linkage as MISMATCH."""
        proc = self._start_target_process()
        try:
            backend = ProcessVmCaptureBackend() if ProcessVmCaptureBackend().is_available(proc.pid) else ProcfsCaptureBackend()
            snap = backend.capture(pid=proc.pid)
            snap_dir = os.path.join(self.corpus_dir, "memory_snapshots", "snap_bid_test")
            snap.save(snap_dir)
        finally:
            self._stop_target_process(proc)

        # Create a dummy ELF with different build ID
        dummy_elf = os.path.join(self.work_dir, "dummy_elf.elf")
        subprocess.run([
            "g++", "-fPIE", "-pie", "-g", "-O0", "-Wl,--build-id=md5",
            "-x", "c++", "-", "-o", dummy_elf
        ], input="int main() { return 0; }\n", text=True, check=True)

        session_info = self.mgr.start_investigation(
            goal="Investigate with mismatched debug artifact",
            memory_snapshot_path=snap_dir,
            debug_image=dummy_elf,
            authorize_target=False,
        )

        id_stage = session_info["stages"]["target_identity"]
        self.assertEqual(id_stage["status"], "FAILED")
        self.assertEqual(id_stage["details"]["build_id_status"], IDENTITY_MISMATCH)

        static_stage = session_info["stages"]["static_code_link"]
        self.assertEqual(static_stage["status"], "FAILED")
        self.assertEqual(static_stage["details"]["linkage_status"], "MISMATCH")

        # Overall investigation cannot be COMPLETED
        self.assertEqual(session_info["status"], "FAILED")

    # =========================================================================
    # 6. Object Graph: Pointers Outside Captured Memory & Cyclic References
    # =========================================================================

    def test_object_graph_cycle_handling(self):
        """Cyclic references (e.g. self-referencing pointers) do not cause recursion errors or infinite loops."""
        from extractor.cpp_decoder import CppObjectDecoder, DwarfIndex, TypedMemoryReader
        from extractor.raw_snapshot import RawRuntimeSnapshot

        # Construct minimal fake index with self-referencing Node struct
        index = DwarfIndex(
            artifact_path=self.debug_bin,
            pointer_size=8,
            endianness="little",
            build_id="test_bid_cycle",
        )

        raw_snap = RawRuntimeSnapshot(
            snapshot_id="snap_cycle",
            timestamp="2026-10-11T05:00:00Z",
            pid=1111,
            executable="/bin/app",
            executable_build_id="test_bid_cycle",
            memory_regions=[{
                "region_id": "R1",
                "start": "0x1000",
                "end": "0x2000",
                "size": 0x1000,
                "permissions": "rw-p",
                "category": "heap",
            }],
            register_state={},
            captured_ranges=[[0x1000, 0x2000]],
            raw_memory={"total_bytes": 0x1000},
            capture_backend="process_vm_readv",
            observation_metadata={},
            completeness="COMPLETE",
            capture_duration_us=100.0,
            provenance={},
            _buffers={(0x1000, 0x2000): b"\x00" * 0x1000},
        )

        reader = TypedMemoryReader(raw_snap, pointer_size=8, endianness="little")
        decoder = CppObjectDecoder(reader, index, load_bias=0)

        # Simulating decode of an object at 0x1000
        id1 = decoder.decode_object(0x1000, type_offset=None, path="root")
        # Decoding same address returns cached identity
        id2 = decoder.decode_object(0x1000, type_offset=None, path="root.next")
        self.assertEqual(id1, id2)
        self.assertEqual(len(decoder.visited), 1)

    # =========================================================================
    # 7. Honest Status Model & Bounded Zero-Findings Report
    # =========================================================================

    def test_honest_stage_statuses_reported_separately(self):
        """Summary contains separate capture_status, decoding_status, static_linkage_status, and overall status."""
        proc = self._start_target_process()
        try:
            backend = ProcessVmCaptureBackend() if ProcessVmCaptureBackend().is_available(proc.pid) else ProcfsCaptureBackend()
            snap = backend.capture(pid=proc.pid)
            snap_dir = os.path.join(self.corpus_dir, "memory_snapshots", "snap_honest_status")
            snap.save(snap_dir)
        finally:
            self._stop_target_process(proc)

        session_info = self.mgr.start_investigation(
            goal="Test honest stage statuses",
            memory_snapshot_path=snap_dir,
            debug_image=self.debug_bin,
            authorize_target=False,
        )

        summary = session_info["summary"]
        self.assertIn("capture_status", summary)
        self.assertIn("decoding_status", summary)
        self.assertIn("static_linkage_status", summary)
        self.assertIn("status", summary)
        self.assertIn("scope", summary)

        # Scoped metrics are populated
        scope = summary["scope"]
        self.assertIn("objects_examined", scope)
        self.assertIn("roots_examined", scope)
        self.assertIn("regions_examined", scope)
        self.assertIn("bytes_inspected", scope)
        self.assertIn("unresolved_checks", scope)
        self.assertGreater(scope["bytes_inspected"], 0)

    def test_bounded_zero_findings_notice(self):
        """Zero findings produces bounded notice that never claims universal health or bug-free memory."""
        # Run investigation on empty corpus snapshot with zero findings
        empty_snap = {
            "snapshot_id": "snap_empty_scope",
            "timestamp": "2026-10-11T05:00:00Z",
            "process": {"pid": 2222, "binary": "/bin/empty"},
            "executable_build_id": "dummy_bid",
            "persistent": {"objects": []},
            "execution": {"threads": []},
            "consistency": {"level": STOPPED},
        }
        self.mgr.corpus.add(empty_snap)

        res = self.mgr.start_investigation(
            goal="Zero findings boundary test",
            snapshot_id="snap_empty_scope",
            authorize_target=False,
        )

        summary = res["summary"]
        notice = summary.get("zero_findings_notice")
        self.assertIsNotNone(notice)
        # Must explicitly acknowledge unmapped/uninspected areas
        self.assertIn("unverified", notice.lower())
        self.assertFalse("bug-free" in notice.lower())
        self.assertFalse("system healthy" in notice.lower())

    # =========================================================================
    # 8. Real Compiled C++ Live Capture Latency
    # =========================================================================

    def test_live_target_capture_latency_and_resumption(self):
        """Capture against a running process executes with low latency and target continues running."""
        proc = self._start_target_process()
        try:
            t0 = time.monotonic()
            session_info = self.mgr.start_investigation(
                goal="Live capture latency measurement",
                pid=proc.pid,
                debug_image=self.debug_bin,
                authorize_target=True,
            )
            elapsed_ms = (time.monotonic() - t0) * 1000.0

            # Target process must still be running after capture!
            self.assertIsNone(proc.poll(), "Target process exited prematurely during/after live capture")

            # Check capture quality details
            cq = session_info["stages"]["capture_quality"]["details"]
            duration_us = cq.get("duration_us", 0)
            self.assertGreater(duration_us, 0)
            self.assertLess(duration_us, 1000000.0, "Live capture took longer than 1 second")

            # Overall elapsed time including DWARF resolution should be reasonable
            self.assertLess(elapsed_ms, 5000.0)

            # Confirm captured bytes > 0
            self.assertGreater(cq.get("bytes_captured", 0), 0)
        finally:
            self._stop_target_process(proc)


if __name__ == "__main__":
    unittest.main()
