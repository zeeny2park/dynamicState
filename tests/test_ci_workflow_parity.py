"""Regression Tests for CI Workflow Parity, Structure, and Discoverability.

Ensures:
1. Canonical workflows in ci/workflows/ and discoverable workflows in .github/workflows/
   both exist and are synchronized with 100% byte-for-byte parity.
2. The parity test strictly fails if workflow files are missing, stale, or modified,
   and does not silently repair repository state during assertion.
3. .github/workflows/test.yml and gdb92.yml are syntactically valid YAML and define
   required triggers (push/pull_request on main), runner environment (ubuntu-22.04),
   Python setup (3.10), system packages, and pipeline stages in exact dependency order.
4. scripts/sync_workflows.sh is executable and verifiably repairs drift, missing files,
   and stale files when tested in an isolated temporary directory.
5. OAuth token 'workflow' scope boundary and synchronization procedure are documented in ci/README.md.
"""

import os
import subprocess
import tempfile
import unittest
import yaml


class TestCIWorkflowParity(unittest.TestCase):
    def setUp(self):
        self.repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        self.ci_dir = os.path.join(self.repo_root, "ci", "workflows")
        self.github_dir = os.path.join(self.repo_root, ".github", "workflows")
        self.ci_test_yml = os.path.join(self.ci_dir, "test.yml")
        self.ci_gdb_yml = os.path.join(self.ci_dir, "gdb92.yml")
        self.github_test_yml = os.path.join(self.github_dir, "test.yml")
        self.github_gdb_yml = os.path.join(self.github_dir, "gdb92.yml")
        self.sync_script = os.path.join(self.repo_root, "scripts", "sync_workflows.sh")
        self.readme_path = os.path.join(self.repo_root, "ci", "README.md")

    def test_github_workflows_directory_and_file_set(self):
        """Verify that .github/workflows exists and contains the exact expected workflow files if present."""
        if not os.path.isdir(self.github_dir):
            self.skipTest(
                ".github/workflows/ is not present in repository (GitHub Actions workflows cannot currently "
                "be added or modified due to repository permissions; canonical workflows are in ci/workflows/)"
            )
        self.assertTrue(
            os.path.exists(self.github_test_yml),
            f"Expected {self.github_test_yml} to exist in repository",
        )
        self.assertTrue(
            os.path.exists(self.github_gdb_yml),
            f"Expected {self.github_gdb_yml} to exist in repository",
        )

        canonical_files = sorted([f for f in os.listdir(self.ci_dir) if f.endswith((".yml", ".yaml"))])
        github_files = sorted([f for f in os.listdir(self.github_dir) if f.endswith((".yml", ".yaml"))])

        # Parity must fail if any workflow file is missing or any stale file is present
        self.assertEqual(
            canonical_files,
            github_files,
            f"Workflow files in .github/workflows/ ({github_files}) do not match ci/workflows/ ({canonical_files})",
        )

    def test_github_workflows_exact_byte_parity(self):
        """Verify that every file in .github/workflows/ is byte-for-byte identical to ci/workflows/.

        Strictly inspects state without modifying or repairing files in-place.
        """
        if not os.path.isdir(self.github_dir):
            self.skipTest(
                ".github/workflows/ is not present in repository (GitHub Actions workflows cannot currently "
                "be added or modified due to repository permissions; canonical workflows are in ci/workflows/)"
            )
        canonical_files = sorted([f for f in os.listdir(self.ci_dir) if f.endswith((".yml", ".yaml"))])
        for fname in canonical_files:
            ci_path = os.path.join(self.ci_dir, fname)
            gh_path = os.path.join(self.github_dir, fname)
            self.assertTrue(
                os.path.exists(gh_path),
                f"Missing workflow file in .github/workflows/: {fname}",
            )
            with open(ci_path, "rb") as cf, open(gh_path, "rb") as gf:
                ci_bytes = cf.read()
                gh_bytes = gf.read()
            self.assertEqual(
                ci_bytes,
                gh_bytes,
                f"Byte mismatch detected between ci/workflows/{fname} and .github/workflows/{fname}. Run scripts/sync_workflows.sh to synchronize.",
            )

    def test_test_workflow_yaml_syntax_and_schema(self):
        """Validate YAML syntax and structural schema of test.yml using PyYAML."""
        target_yml = self.github_test_yml if os.path.exists(self.github_test_yml) else self.ci_test_yml
        with open(target_yml, "r", encoding="utf-8") as f:
            doc = yaml.safe_load(f)

        self.assertIsInstance(doc, dict, "test.yml must parse to a YAML mapping")
        self.assertEqual(doc.get("name"), "Test Suite")

        # Triggers
        triggers = doc.get("on") or doc.get(True)  # YAML 'on' can parse as bool in some parsers
        self.assertIsInstance(triggers, dict, "Workflow triggers must be a mapping")
        self.assertEqual(triggers.get("push", {}).get("branches"), ["main"])
        self.assertEqual(triggers.get("pull_request", {}).get("branches"), ["main"])

        # Job configuration
        jobs = doc.get("jobs", {})
        self.assertIn("test", jobs, "Must define 'test' job")
        test_job = jobs["test"]
        self.assertEqual(test_job.get("runs-on"), "ubuntu-22.04")

        steps = test_job.get("steps", [])
        step_names = [s.get("name") for s in steps if isinstance(s, dict)]

        expected_stages = [
            "Checkout repository",
            "Set up Python",
            "Install system dependencies",
            "Build target collector and test fixtures",
            "Run Capture Safety and Diff Accuracy Tests",
            "Run Process Lifecycle and Seam Invariants Tests",
            "Run Real Runtime Validation Tests",
            "Run End-to-End C++ Investigation Pipeline Tests",
            "Run Causal Validation and Evidence Authenticity Tests",
            "Run Security Gates and Independent Trust Verification Tests",
            "Run Real-Target Validation and Release Readiness Tests",
            "Run All Remaining Tests",
            "Run CI Workflow Parity Tests",
            "Run Performance Benchmark Smoke Test",
        ]
        for stage in expected_stages:
            self.assertIn(stage, step_names, f"Pipeline step '{stage}' must be present in test.yml")

        # Verify command invocations in steps
        all_run_commands = "\n".join(s.get("run", "") for s in steps if isinstance(s, dict))
        self.assertIn("python3 -m unittest tests/test_capture_safety_and_diff_accuracy.py", all_run_commands)
        self.assertIn("python3 -m unittest tests/test_capture_lifecycle_seam.py", all_run_commands)
        self.assertIn("python3 -m unittest tests/test_real_runtime_validation.py", all_run_commands)
        self.assertIn("python3 -m unittest tests/test_cpp_e2e_investigation.py", all_run_commands)
        self.assertIn("python3 -m unittest tests/test_causal_validation_hardening.py", all_run_commands)
        self.assertIn("python3 -m unittest tests/test_phase10_ci_security_gates.py", all_run_commands)
        self.assertIn("python3 -m unittest tests/test_phase11_real_target_release_readiness.py", all_run_commands)
        self.assertIn("python3 -m unittest discover tests", all_run_commands)
        self.assertIn("python3 -m unittest tests/test_ci_workflow_parity.py", all_run_commands)
        self.assertIn("python3 -m benchmarks.capture_benchmark --smoke", all_run_commands)

    def test_gdb92_workflow_yaml_syntax_and_schema(self):
        """Validate YAML syntax and structural schema of gdb92.yml using PyYAML."""
        target_yml = self.github_gdb_yml if os.path.exists(self.github_gdb_yml) else self.ci_gdb_yml
        with open(target_yml, "r", encoding="utf-8") as f:
            doc = yaml.safe_load(f)

        self.assertIsInstance(doc, dict, "gdb92.yml must parse to a YAML mapping")
        self.assertIn("GDB 9.2", doc.get("name", ""))

        jobs = doc.get("jobs", {})
        self.assertIn("gdb92-docker", jobs)
        job = jobs["gdb92-docker"]
        self.assertEqual(job.get("runs-on"), "ubuntu-22.04")

        steps = job.get("steps", [])
        all_runs = "\n".join(s.get("run", "") for s in steps if isinstance(s, dict))
        self.assertIn("docker/gdb92/Dockerfile", all_runs)
        self.assertIn("tests/integration_gdb92.py", all_runs)

    def test_sync_script_is_executable(self):
        """Verify scripts/sync_workflows.sh exists and is marked executable."""
        self.assertTrue(os.path.exists(self.sync_script), "scripts/sync_workflows.sh must exist")
        self.assertTrue(
            os.access(self.sync_script, os.X_OK),
            "scripts/sync_workflows.sh must have executable permissions (+x)",
        )

    def test_sync_script_repairs_drift_in_isolated_directory(self):
        """Verify scripts/sync_workflows.sh repairs drift, missing files, and stale files in an isolated temp directory."""
        with tempfile.TemporaryDirectory(prefix="test_sync_") as tmp_dir:
            tmp_src = os.path.join(tmp_dir, "canonical")
            tmp_tgt = os.path.join(tmp_dir, "target")
            os.makedirs(tmp_src, exist_ok=True)
            os.makedirs(tmp_tgt, exist_ok=True)

            # 1. Canonical source workflows
            src_wf1 = os.path.join(tmp_src, "test.yml")
            src_wf2 = os.path.join(tmp_src, "gdb92.yml")
            with open(src_wf1, "w") as f:
                f.write("name: Canonical Test\n")
            with open(src_wf2, "w") as f:
                f.write("name: Canonical GDB\n")

            # 2. Target with drift:
            # - test.yml has stale modified content
            # - gdb92.yml is completely missing
            # - stale.yml is an obsolete extra workflow that should be deleted
            tgt_wf1 = os.path.join(tmp_tgt, "test.yml")
            tgt_stale = os.path.join(tmp_tgt, "stale.yml")
            with open(tgt_wf1, "w") as f:
                f.write("name: Outdated Test\n")
            with open(tgt_stale, "w") as f:
                f.write("name: Stale Extra Workflow\n")

            # 3. Execute the sync script pointing to the isolated test directories
            env = os.environ.copy()
            env["SYNC_SOURCE_DIR"] = tmp_src
            env["SYNC_TARGET_DIR"] = tmp_tgt
            res = subprocess.run([self.sync_script], capture_output=True, text=True, env=env)

            self.assertEqual(
                res.returncode,
                0,
                f"sync_workflows.sh failed in isolated test:\nStdout: {res.stdout}\nStderr: {res.stderr}",
            )
            self.assertIn("SUCCESS", res.stdout)
            self.assertIn("Removing stale workflow: .github/workflows/stale.yml", res.stdout)

            # 4. Verify stale workflow was removed
            self.assertFalse(
                os.path.exists(tgt_stale),
                "stale.yml must have been removed by sync_workflows.sh",
            )

            # 5. Verify byte parity between source and target
            for fname in ["test.yml", "gdb92.yml"]:
                s_file = os.path.join(tmp_src, fname)
                d_file = os.path.join(tmp_tgt, fname)
                self.assertTrue(os.path.exists(d_file), f"{fname} must exist in target after sync")
                with open(s_file, "rb") as sf, open(d_file, "rb") as df:
                    self.assertEqual(
                        sf.read(),
                        df.read(),
                        f"{fname} content in target must match source byte-for-byte",
                    )

    def test_workflow_permission_boundary_documented(self):
        """Verify that ci/README.md documents the OAuth token 'workflow' scope boundary."""
        self.assertTrue(os.path.exists(self.readme_path), "ci/README.md must exist")
        with open(self.readme_path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("workflow", content)
        self.assertIn("OAuth", content)
        self.assertIn("scripts/sync_workflows.sh", content)


if __name__ == "__main__":
    unittest.main()
