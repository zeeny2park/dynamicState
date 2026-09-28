#!/usr/bin/env python3
"""Unit tests for dynamic-state CLI interface."""

import json
import subprocess
import sys
import unittest


class TestCli(unittest.TestCase):
    def test_cli_help(self):
        res = subprocess.run(
            [sys.executable, "-m", "extractor.cli", "--help"],
            capture_output=True,
            text=True
        )
        self.assertEqual(res.returncode, 0)
        self.assertIn("capture-memory", res.stdout)
        self.assertIn("analyze-memory", res.stdout)
        self.assertIn("list-modules", res.stdout)
        self.assertIn("runtime-info", res.stdout)
        self.assertIn("extract-state", res.stdout)

    def test_cli_runtime_info(self):
        res = subprocess.run(
            [sys.executable, "-m", "extractor.cli", "runtime-info"],
            capture_output=True,
            text=True
        )
        self.assertEqual(res.returncode, 0)
        info = json.loads(res.stdout)
        self.assertIn("observation_modes", info)
        self.assertIn("LOW_IMPACT", info["observation_modes"])
        self.assertIn("CONSISTENT", info["observation_modes"])
        self.assertIn("low_impact_safety", info)
        self.assertFalse(info["low_impact_safety"]["process_stop"])
        self.assertFalse(info["low_impact_safety"]["ptrace"])

    def test_cli_extract_state_help(self):
        res = subprocess.run(
            [sys.executable, "-m", "extractor.cli", "extract-state", "--help"],
            capture_output=True,
            text=True
        )
        self.assertEqual(res.returncode, 0)
        self.assertIn("--mode", res.stdout)
        self.assertIn("--debug-image", res.stdout)
        self.assertIn("--pid", res.stdout)

    def test_cli_extract_state_low_impact_missing_pid(self):
        res = subprocess.run(
            [sys.executable, "-m", "extractor.cli", "extract-state", "--mode", "LOW_IMPACT"],
            capture_output=True,
            text=True
        )
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("--pid is required", res.stderr)

    def test_cli_extract_state_low_impact_missing_debug_image(self):
        res = subprocess.run(
            [sys.executable, "-m", "extractor.cli", "extract-state", "--mode", "LOW_IMPACT", "--pid", "1234"],
            capture_output=True,
            text=True
        )
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("--debug-image is required", res.stderr)


if __name__ == "__main__":
    unittest.main()
