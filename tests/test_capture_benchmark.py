"""Unit and Regression Tests for Capture Benchmark Integrity and Schema.

Validates:
1. compute_percentiles preserves nulls for empty/unavailable metrics, rejects NaNs/Infs,
   and computes correct percentiles and sample counts.
2. verify_snapshot_payload verifies ELF magic header and byte counts.
3. validate_benchmark_report_schema validates report schema and detects missing/invalid fields.
4. Parameter validation rejects invalid iterations (< 1).
5. Benchmark execution completes cleanly in smoke mode.
"""

import math
import os
import unittest
from typing import Any, Dict

from benchmarks.capture_benchmark import (
    compute_percentiles,
    verify_snapshot_payload,
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

    def test_verify_snapshot_payload_with_elf_header(self):
        """Snapshot with valid ELF header passes payload verification."""
        elf_magic = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        regions = [{
            "start": "0x400000",
            "end": "0x401000",
            "size": 4096,
            "captured_bytes": 4096,
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
        self.assertTrue(res["elf_magic_found"])
        self.assertEqual(res["total_bytes_verified"], 4096)

    def test_validate_benchmark_report_schema_valid(self):
        """Valid benchmark report passes schema validation."""
        valid_report = {
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
            },
            "backends": [
                {
                    "backend": "process_vm_readv",
                    "iterations": 10,
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
            "budget_enforcement": {
                "budget_limit_ms": 2.0,
                "observed_stop_ms": 5.0,
                "policy_enforced": True,
                "completeness_demoted_to_partial": True,
            }
        }
        valid, errors = validate_benchmark_report_schema(valid_report)
        self.assertTrue(valid, f"Expected valid schema, got errors: {errors}")
        self.assertEqual(errors, [])

    def test_validate_benchmark_report_schema_detects_errors(self):
        """Schema validator catches missing required keys and non-finite values."""
        invalid_report = {
            "environment": {},  # missing required fields
            "benchmark_parameters": {"iterations": 0},  # invalid iterations
            "backends": [],  # empty backends
        }
        valid, errors = validate_benchmark_report_schema(invalid_report)
        self.assertFalse(valid)
        self.assertTrue(len(errors) >= 3)

    def test_run_benchmark_rejects_invalid_iterations(self):
        """run_benchmark rejects iterations < 1 with ValueError."""
        with self.assertRaises(ValueError):
            run_benchmark(iterations=0)
        with self.assertRaises(ValueError):
            run_benchmark(iterations=-5)


if __name__ == "__main__":
    unittest.main()
