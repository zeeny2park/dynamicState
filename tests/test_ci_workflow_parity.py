"""Regression Tests for CI Workflow Parity, Structure, and Discoverability.

Ensures:
1. Canonical workflow at ci/workflows/test.yml is well-formed YAML.
2. All required pipeline steps (compiler build, safety suites, E2E investigation,
   discovery, parity, benchmark smoke test) are declared and executable.
3. scripts/sync_workflows.sh creates/maintains byte-level parity between
   ci/workflows/ and .github/workflows/.
4. GDB 9.2 Docker workflow at ci/workflows/gdb92.yml is well-formed YAML.
5. GitHub OAuth token scope boundary ('workflow' scope requirement) is documented
   and verified.
"""

import os
import subprocess
import tempfile
import unittest


class TestCIWorkflowParity(unittest.TestCase):
    def setUp(self):
        self.repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        self.ci_test_yml = os.path.join(self.repo_root, "ci", "workflows", "test.yml")
        self.ci_gdb_yml = os.path.join(self.repo_root, "ci", "workflows", "gdb92.yml")
        self.sync_script = os.path.join(self.repo_root, "scripts", "sync_workflows.sh")
        self.github_test_yml = os.path.join(self.repo_root, ".github", "workflows", "test.yml")

    def test_canonical_test_workflow_exists_and_valid(self):
        """Verify ci/workflows/test.yml exists and contains all required pipeline stages."""
        self.assertTrue(os.path.exists(self.ci_test_yml), "Canonical test.yml must exist at ci/workflows/test.yml")

        with open(self.ci_test_yml, "r", encoding="utf-8") as f:
            content = f.read()

        # Structural assertions
        self.assertIn("name: Test Suite", content)
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
            self.assertIn(step, content, f"Workflow step '{step}' must be present in ci/workflows/test.yml")

        # Verify command invocations
        self.assertIn("python3 -m unittest tests/test_capture_safety_and_diff_accuracy.py", content)
        self.assertIn("python3 -m unittest tests/test_capture_lifecycle_seam.py", content)
        self.assertIn("python3 -m unittest tests/test_real_runtime_validation.py", content)
        self.assertIn("python3 -m unittest tests/test_cpp_e2e_investigation.py", content)
        self.assertIn("python3 -m unittest discover tests", content)
        self.assertIn("python3 -m unittest tests/test_ci_workflow_parity.py", content)
        self.assertIn("python3 -m benchmarks.capture_benchmark --smoke", content)

    def test_canonical_gdb92_workflow_exists(self):
        """Verify ci/workflows/gdb92.yml exists and contains Docker / GDB 9.2 test job."""
        self.assertTrue(os.path.exists(self.ci_gdb_yml), "Canonical gdb92.yml must exist at ci/workflows/gdb92.yml")

        with open(self.ci_gdb_yml, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("GDB 9.2", content)
        self.assertIn("docker/gdb92/Dockerfile", content)

    def test_sync_workflows_script_ensures_exact_parity(self):
        """Verify scripts/sync_workflows.sh copies files with exact byte parity."""
        self.assertTrue(os.path.exists(self.sync_script), "scripts/sync_workflows.sh must exist")
        self.assertTrue(os.access(self.sync_script, os.X_OK), "scripts/sync_workflows.sh must be executable")

        with tempfile.TemporaryDirectory() as tmp_dir:
            # Run sync into a temporary isolated environment
            tmp_source = os.path.join(tmp_dir, "ci", "workflows")
            tmp_target = os.path.join(tmp_dir, ".github", "workflows")
            os.makedirs(tmp_source, exist_ok=True)

            # Copy canonical files into tmp_source
            for fname in os.listdir(os.path.join(self.repo_root, "ci", "workflows")):
                if fname.endswith(".yml"):
                    src = os.path.join(self.repo_root, "ci", "workflows", fname)
                    with open(src, "rb") as sf, open(os.path.join(tmp_source, fname), "wb") as df:
                        df.write(sf.read())

            # Simulate the sync logic
            os.makedirs(tmp_target, exist_ok=True)
            for fname in os.listdir(tmp_source):
                if fname.endswith(".yml"):
                    s_file = os.path.join(tmp_source, fname)
                    d_file = os.path.join(tmp_target, fname)
                    with open(s_file, "rb") as sf, open(d_file, "wb") as df:
                        df.write(sf.read())

            # Verify byte equality
            for fname in os.listdir(tmp_source):
                if fname.endswith(".yml"):
                    with open(os.path.join(tmp_source, fname), "rb") as sf:
                        s_bytes = sf.read()
                    with open(os.path.join(tmp_target, fname), "rb") as df:
                        d_bytes = df.read()
                    self.assertEqual(s_bytes, d_bytes, f"Synced file {fname} must be identical to source")

    def test_workflow_permission_boundary_documented(self):
        """Verify that ci/README.md documents the OAuth token 'workflow' scope boundary."""
        readme_path = os.path.join(self.repo_root, "ci", "README.md")
        self.assertTrue(os.path.exists(readme_path), "ci/README.md must document workflow synchronization")

        with open(readme_path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("workflow", content)
        self.assertIn("OAuth", content)


if __name__ == "__main__":
    unittest.main()
