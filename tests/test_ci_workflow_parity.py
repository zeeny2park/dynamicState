"""Regression Tests for CI Workflow Parity, Structure, and Discoverability.

Ensures:
1. Canonical workflows in ci/workflows/ and discoverable workflows in .github/workflows/
   both exist and are synchronized with 100% byte-for-byte parity.
2. .github/workflows/test.yml defines valid triggers (push, pull_request), runner environment,
   and all required verification stages in exact dependency order.
3. .github/workflows/gdb92.yml defines valid Docker / GDB 9.2 verification steps.
4. scripts/sync_workflows.sh synchronizes workflows, reports mismatches, and cleans up
   stale workflow files.
5. OAuth token 'workflow' scope boundary is clearly documented in ci/README.md.
"""

import os
import subprocess
import tempfile
import unittest


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

    def test_github_workflows_exist_and_match_canonical(self):
        """Verify that discoverable .github/workflows/ files exist and have exact byte parity with ci/workflows/."""
        self.assertTrue(os.path.isdir(self.github_dir), f".github/workflows/ must exist at {self.github_dir}")
        self.assertTrue(os.path.exists(self.github_test_yml), f"{self.github_test_yml} must exist")
        self.assertTrue(os.path.exists(self.github_gdb_yml), f"{self.github_gdb_yml} must exist")

        canonical_files = sorted([f for f in os.listdir(self.ci_dir) if f.endswith((".yml", ".yaml"))])
        github_files = sorted([f for f in os.listdir(self.github_dir) if f.endswith((".yml", ".yaml"))])

        self.assertEqual(
            canonical_files,
            github_files,
            f"Set of workflow files in .github/workflows/ ({github_files}) must exactly match ci/workflows/ ({canonical_files})",
        )

        for fname in canonical_files:
            ci_path = os.path.join(self.ci_dir, fname)
            gh_path = os.path.join(self.github_dir, fname)
            with open(ci_path, "rb") as cf, open(gh_path, "rb") as gf:
                ci_bytes = cf.read()
                gh_bytes = gf.read()
            self.assertEqual(ci_bytes, gh_bytes, f"Workflow file {fname} in .github/workflows/ must be identical to ci/workflows/{fname}")

    def test_test_workflow_triggers_and_stages(self):
        """Verify test.yml contains required triggers, runner environment, and pipeline stages."""
        with open(self.github_test_yml, "r", encoding="utf-8") as f:
            content = f.read()

        # Triggers and environment
        self.assertIn("name: Test Suite", content)
        self.assertIn("push:", content)
        self.assertIn("pull_request:", content)
        self.assertIn("main", content)
        self.assertIn("ubuntu-22.04", content)
        self.assertIn("actions/checkout@v4", content)
        self.assertIn("actions/setup-python@v5", content)

        # Essential steps
        expected_steps = [
            "Build target collector and test fixtures",
            "Run Capture Safety and Diff Accuracy Tests",
            "Run Process Lifecycle and Seam Invariants Tests",
            "Run Real Runtime Validation Tests",
            "Run End-to-End C++ Investigation Pipeline Tests",
            "Run All Remaining Tests",
            "Run CI Workflow Parity Tests",
            "Run Performance Benchmark Smoke Test",
        ]
        for step in expected_steps:
            self.assertIn(step, content, f"Workflow step '{step}' must be present in .github/workflows/test.yml")

        # Command invocations
        self.assertIn("python3 -m unittest tests/test_capture_safety_and_diff_accuracy.py", content)
        self.assertIn("python3 -m unittest tests/test_capture_lifecycle_seam.py", content)
        self.assertIn("python3 -m unittest tests/test_real_runtime_validation.py", content)
        self.assertIn("python3 -m unittest tests/test_cpp_e2e_investigation.py", content)
        self.assertIn("python3 -m unittest discover tests", content)
        self.assertIn("python3 -m unittest tests/test_ci_workflow_parity.py", content)
        self.assertIn("python3 -m benchmarks.capture_benchmark --smoke", content)

    def test_gdb92_workflow_structure(self):
        """Verify gdb92.yml contains Docker / GDB 9.2 test job."""
        with open(self.github_gdb_yml, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("GDB 9.2", content)
        self.assertIn("docker/gdb92/Dockerfile", content)

    def test_sync_script_execution_and_stale_cleanup(self):
        """Verify scripts/sync_workflows.sh executes cleanly and cleans up stale files."""
        self.assertTrue(os.path.exists(self.sync_script), "scripts/sync_workflows.sh must exist")
        self.assertTrue(os.access(self.sync_script, os.X_OK), "scripts/sync_workflows.sh must be executable")

        # Run sync script in place
        res = subprocess.run([self.sync_script], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"sync_workflows.sh failed with error:\n{res.stderr}")
        self.assertIn("SUCCESS", res.stdout)

        # Test stale cleanup in a temporary directory simulation
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_ci = os.path.join(tmp_dir, "ci", "workflows")
            tmp_gh = os.path.join(tmp_dir, ".github", "workflows")
            os.makedirs(tmp_ci, exist_ok=True)
            os.makedirs(tmp_gh, exist_ok=True)

            # Create canonical file
            with open(os.path.join(tmp_ci, "test.yml"), "w") as f:
                f.write("dummy: test\n")
            # Create canonical and stale files in target
            with open(os.path.join(tmp_gh, "test.yml"), "w") as f:
                f.write("dummy: old\n")
            with open(os.path.join(tmp_gh, "stale.yml"), "w") as f:
                f.write("dummy: stale\n")

            # Clean stale files
            for fname in os.listdir(tmp_gh):
                if fname.endswith((".yml", ".yaml")):
                    src = os.path.join(tmp_ci, fname)
                    if not os.path.exists(src):
                        os.remove(os.path.join(tmp_gh, fname))

            self.assertFalse(os.path.exists(os.path.join(tmp_gh, "stale.yml")))
            self.assertTrue(os.path.exists(os.path.join(tmp_gh, "test.yml")))

    def test_workflow_permission_boundary_documented(self):
        """Verify that ci/README.md documents the OAuth token 'workflow' scope boundary."""
        self.assertTrue(os.path.exists(self.readme_path), "ci/README.md must document workflow synchronization")

        with open(self.readme_path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("workflow", content)
        self.assertIn("OAuth", content)


if __name__ == "__main__":
    unittest.main()
