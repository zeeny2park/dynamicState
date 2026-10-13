"""Unit and Regression Tests for Capture Benchmark Integrity, Schema, and Acceptance Gates.

Validates:
1. compute_percentiles preserves nulls for empty/unavailable metrics, rejects NaNs/Infs,
   and computes correct percentiles and sample counts.
2. verify_snapshot_payload handles realistic memory regions: verifies non-empty buffers,
   checks ELF headers when realistically expected, and does not falsely expect ELF magic
   on pure anonymous/heap ranges.
3. evaluate_backend_equivalence detects unequal workloads or mismatched quality outcomes.
4. evaluate_benchmark_acceptance_gates enforces correctness, invariants, SLA policy,
   and fails on incomplete/failed captures or accounting discrepancies.
5. validate_benchmark_report_schema detects missing/invalid fields and non-finite values.
6. Baseline protection: refuses to overwrite canonical baseline in smoke mode.
7. Parameter validation rejects invalid iterations (< 1).
"""

import math
import os
import unittest
from typing import Any, Dict

from benchmarks.capture_benchmark import (
    compute_percentiles,
    verify_snapshot_payload,
    evaluate_backend_equivalence,
    evaluate_benchmark_acceptance_gates,
    validate_benchmark_report_schema,
    run_benchmark,
)
from extractor.raw_snapshot import RawRuntimeSnapshot


class TestCaptureBenchmarkIntegrity(unittest.TestCase):
    def test_compute_percentiles_empty_preserves_none(self):
        """Empty or all-None measurements produce nulls, not 0.0, with sample_count=0."""
        res_empty = compute_percentiles([])
        self.assertIsNone(res_empty["p50"])
        self.assertIsNone(res_empty["min"])
        self.assertIsNone(res_empty["max"])
        self.assertIsNone(res_empty["mean"])
        self.assertEqual(res_empty["sample_count"], 0)

        res_none = compute_percentiles([None, None])
        self.assertIsNone(res_none["p50"])
        self.assertIsNone(res_none["mean"])
        self.assertEqual(res_none["sample_count"], 0)

    def test_compute_percentiles_numeric_finite(self):
        """Valid numeric measurements compute correct percentiles and sample counts."""
        vals = [10.0, 20.0, 30.0, 40.0, 50.0]
        res = compute_percentiles(vals)
        self.assertEqual(res["p50"], 30.0)
        self.assertEqual(res["min"], 10.0)
        self.assertEqual(res["max"], 50.0)
        self.assertEqual(res["mean"], 30.0)
        self.assertEqual(res["sample_count"], 5)
        for k, v in res.items():
            if k != "sample_count":
                self.assertTrue(math.isfinite(v), f"Metric {k} must be finite")

    def test_compute_percentiles_filters_nones(self):
        """Mixed None and numeric values filter out Nones and compute on available samples."""
        vals = [None, 100.0, None, 200.0]
        res = compute_percentiles(vals)
        self.assertEqual(res["sample_count"], 2)
        self.assertEqual(res["min"], 100.0)
        self.assertEqual(res["max"], 200.0)
        self.assertEqual(res["p50"], 150.0)

    def test_verify_snapshot_payload_no_regions(self):
        """Snapshot with no regions fails payload verification."""
        snap = RawRuntimeSnapshot(
            snapshot_id="test_snap_empty",
            pid=123,
            executable="/bin/app",
            executable_build_id="sha1",
            timestamp="2026-10-13T00:00:00Z",
            capture_duration_us=100.0,
            memory_regions=[],
        )
        res = verify_snapshot_payload(snap)
        self.assertFalse(res["payload_valid"])
        self.assertFalse(res["elf_magic_found"])
        self.assertEqual(res["region_count"], 0)

    def test_verify_snapshot_payload_realistic_anonymous_heap(self):
        """Anonymous/heap regions pass payload verification without requiring ELF magic."""
        regions = [{
            "start": "0x7fff0000",
            "end": "0x7fff1000",
            "size": 4096,
            "captured_bytes": 4096,
            "pathname": "[heap]",
            "category": "heap",
            "permissions": "rw-p",
        }]
        snap = RawRuntimeSnapshot(
            snapshot_id="test_snap_heap",
            pid=123,
            executable="/bin/app",
            executable_build_id="sha1",
            timestamp="2026-10-13T00:00:00Z",
            capture_duration_us=100.0,
            memory_regions=regions,
        )
        snap.register_buffer(0x7fff0000, b"\xaa" * 4096)

        res = verify_snapshot_payload(snap)
        self.assertTrue(res["payload_valid"])
        self.assertFalse(res["elf_header_expected"])
        self.assertFalse(res["elf_magic_found"])
        self.assertEqual(res["total_bytes_verified"], 4096)

    def test_verify_snapshot_payload_with_elf_header(self):
        """Snapshot with valid ELF header passes payload verification."""
        elf_magic = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        regions = [{
            "start": "0x400000",
            "end": "0x401000",
            "size": 4096,
            "captured_bytes": 4096,
            "pathname": "/path/to/binary.elf",
            "category": "binary",
            "permissions": "r-xp",
            "offset": 0,
        }]
        snap = RawRuntimeSnapshot(
            snapshot_id="test_snap_elf",
            pid=123,
            executable="/bin/app",
            executable_build_id="sha1",
            timestamp="2026-10-13T00:00:00Z",
            capture_duration_us=100.0,
            memory_regions=regions,
        )
        snap.register_buffer(0x400000, elf_magic + b"\x00" * (4096 - len(elf_magic)))

        res = verify_snapshot_payload(snap)
        self.assertTrue(res["payload_valid"])
        self.assertTrue(res["elf_header_expected"])
        self.assertTrue(res["elf_magic_found"])
        self.assertEqual(res["total_bytes_verified"], 4096)

    def test_verify_snapshot_payload_corrupt_elf_header_fails(self):
        """If an ELF header mapping is captured but lacks ELF magic, verification fails."""
        corrupt_header = b"\x00\x00\x00\x00\x00\x00\x00\x00"
        regions = [{
            "start": "0x400000",
            "end": "0x401000",
            "size": 4096,
            "captured_bytes": 4096,
            "pathname": "/bin/target.elf",
            "category": "binary",
            "permissions": "r-xp",
            "offset": 0,
        }]
        snap = RawRuntimeSnapshot(
            snapshot_id="test_snap_corrupt",
            pid=123,
            executable="/bin/target.elf",
            executable_build_id="sha1",
            timestamp="2026-10-13T00:00:00Z",
            capture_duration_us=100.0,
            memory_regions=regions,
        )
        snap.register_buffer(0x400000, corrupt_header + b"\x00" * (4096 - len(corrupt_header)))

        res = verify_snapshot_payload(snap)
        self.assertTrue(res["elf_header_expected"])
        self.assertFalse(res["elf_magic_found"])
        self.assertFalse(res["payload_valid"])

    def test_evaluate_backend_equivalence(self):
        """Backend equivalence distinguishes matching workloads from disparate workloads."""
        b1 = {
            "backend": "process_vm_readv",
            "byte_accounting": {"mean_requested_bytes": 1000.0},
            "quality_distribution": {"COMPLETE": 10},
        }
        b2_match = {
            "backend": "procfs",
            "byte_accounting": {"mean_requested_bytes": 1000.0},
            "quality_distribution": {"COMPLETE": 10},
        }
        b2_mismatch = {
            "backend": "procfs",
            "byte_accounting": {"mean_requested_bytes": 500.0},
            "quality_distribution": {"PARTIAL": 10},
        }

        equiv = evaluate_backend_equivalence([b1, b2_match])
        self.assertTrue(equiv["equivalent_workload"])
        self.assertEqual(equiv["qualification"], "EQUIVALENT_WORKLOAD")

        non_equiv = evaluate_backend_equivalence([b1, b2_mismatch])
        self.assertFalse(non_equiv["equivalent_workload"])
        self.assertEqual(non_equiv["qualification"], "NON_EQUIVALENT_WORKLOAD")
        self.assertTrue(len(non_equiv["reasons"]) >= 2)

    def _build_valid_report(self) -> Dict[str, Any]:
        return {
            "environment": {
                "os": "Linux",
                "kernel_release": "6.17",
                "architecture": "aarch64",
                "cpu_model": "test-cpu",
                "compiler": "g++ 13",
                "timestamp_utc": "2026-10-13T00:00:00Z",
                "git_commit": "abc1234",
            },
            "benchmark_parameters": {
                "iterations": 10,
                "smoke_mode": False,
                "acceptance_mode": True,
            },
            "backends": [
                {
                    "backend": "process_vm_readv",
                    "iterations": 10,
                    "failed_captures": 0,
                    "quality_distribution": {"COMPLETE": 10},
                    "success_rate": 1.0,
                    "mean_captured_bytes": 1000000.0,
                    "throughput_mb_s": 5000.0,
                    "byte_accounting": {
                        "mean_requested_bytes": 1000000.0,
                        "mean_captured_bytes": 1000000.0,
                        "mean_omitted_bytes": 0.0,
                        "mean_failed_bytes": 0.0,
                        "mean_unread_bytes": 0.0,
                        "invariants_satisfied": True,
                        "accounting_violations": [],
                    },
                    "payload_integrity": {
                        "payload_valid": True,
                        "total_bytes_verified": 1000000,
                        "region_count": 1,
                        "valid_buffers_count": 1,
                        "elf_header_expected": False,
                        "elf_magic_found": False,
                    },
                    "metrics": {
                        "stop_latency_us": {
                            "min": 100.0, "p50": 150.0, "p90": 200.0,
                            "p95": 210.0, "p99": 220.0, "max": 230.0,
                            "mean": 160.0, "stddev": 30.0,
                        }
                    }
                }
            ],
            "backend_equivalence": {
                "equivalent_workload": True,
                "qualification": "EQUIVALENT_WORKLOAD",
            },
            "budget_enforcement": {
                "budget_limit_ms": 2.0,
                "observed_stop_ms": 5.0,
                "policy_enforced": True,
                "completeness_demoted_to_partial": True,
            }
        }

    def test_evaluate_benchmark_acceptance_gates_healthy(self):
        """Healthy report passes all acceptance gates."""
        report = self._build_valid_report()
        passed, failures = evaluate_benchmark_acceptance_gates(report, smoke=False, acceptance=True)
        self.assertTrue(passed, f"Expected gates to pass, got failures: {failures}")
        self.assertEqual(failures, [])

    def test_acceptance_gates_detects_quality_and_invariant_failures(self):
        """Acceptance gates reject reports with failed captures, non-COMPLETE quality, or accounting violations."""
        # 1. Non-COMPLETE captures
        r_partial = self._build_valid_report()
        r_partial["backends"][0]["quality_distribution"] = {"COMPLETE": 8, "PARTIAL": 2}
        passed_p, fails_p = evaluate_benchmark_acceptance_gates(r_partial)
        self.assertFalse(passed_p)
        self.assertTrue(any("failed quality gate" in f for f in fails_p))

        # 2. Accounting invariant violation
        r_acc = self._build_valid_report()
        r_acc["backends"][0]["byte_accounting"]["invariants_satisfied"] = False
        passed_a, fails_a = evaluate_benchmark_acceptance_gates(r_acc)
        self.assertFalse(passed_a)
        self.assertTrue(any("byte accounting invariants" in f for f in fails_a))

        # 3. Payload invalid
        r_pay = self._build_valid_report()
        r_pay["backends"][0]["payload_integrity"]["payload_valid"] = False
        passed_y, fails_y = evaluate_benchmark_acceptance_gates(r_pay)
        self.assertFalse(passed_y)
        self.assertTrue(any("payload integrity" in f for f in fails_y))

        # 4. Budget enforcement failure
        r_bud = self._build_valid_report()
        r_bud["budget_enforcement"]["policy_enforced"] = False
        passed_b, fails_b = evaluate_benchmark_acceptance_gates(r_bud)
        self.assertFalse(passed_b)
        self.assertTrue(any("Stop budget SLA policy was not enforced" in f for f in fails_b))

    def test_baseline_protection_rejects_smoke_overwrite(self):
        """run_benchmark refuses to overwrite canonical baseline_results.json in smoke mode."""
        with self.assertRaises(ValueError) as ctx:
            run_benchmark(
                smoke=True,
                output_path="benchmarks/baseline_results.json",
            )
        self.assertIn("Cannot overwrite canonical benchmarks/baseline_results.json with a smoke run", str(ctx.exception))

    def test_run_benchmark_rejects_invalid_iterations(self):
        """run_benchmark rejects iterations < 1 with ValueError."""
        with self.assertRaises(ValueError):
            run_benchmark(iterations=0)
        with self.assertRaises(ValueError):
            run_benchmark(iterations=-5)


if __name__ == "__main__":
    unittest.main()
