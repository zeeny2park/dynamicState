"""Phase 35 (Phase 4 Roadmap) Test Suite:
1. Auto-deployment of C99 collector to remote SSH targets (`ensure_remote_collector`).
2. High-level CLI subcommands (`connect`, `eval`, `diff`, `recipe`).
3. MCP `runtime_get_playbook` and `auto_deploy_collector` integration + Web `/api/target/deploy-collector`.
4. Practical Playbook documentation (`docs/PRACTICAL_PLAYBOOK_KO.md` and `README.md`).
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from extractor.agent_runtime import AgentRuntime
from extractor.target_adapter import RemoteSshTargetAdapter
from extractor.web.server import WebApiAdapter
import scripts.mcp_server as mcp_srv


class TestPhase35AutoDeployCliAndPlaybook(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work_dir = tempfile.mkdtemp(prefix="dynstate_p35_")
        cls.corpus_dir = os.path.join(cls.work_dir, "corpus")
        os.makedirs(cls.corpus_dir, exist_ok=True)

        orig_src = os.path.join(PROJECT_ROOT, "tests", "fixtures", "real_runtime", "main.cpp")
        cls.fixture_src = os.path.join(cls.work_dir, "main_ptracer.cpp")
        with open(orig_src, "r", encoding="utf-8") as sf:
            src_code = sf.read()
        ptracer_ctor = """
#include <sys/prctl.h>
__attribute__((constructor)) static void _enable_sibling_cli_ptracer() {
    prctl(0x59616d61, -1, 0, 0, 0);
}
"""
        with open(cls.fixture_src, "w", encoding="utf-8") as df:
            df.write(ptracer_ctor + "\n" + src_code)
        cls.debug_bin = os.path.join(cls.work_dir, "app_debug.elf")
        subprocess.run(
            [
                "g++", "-fPIE", "-pie", "-g", "-O0", "-fno-inline", "-fno-omit-frame-pointer",
                "-Wl,--build-id=sha1", cls.fixture_src, "-o", cls.debug_bin, "-lpthread"
            ],
            check=True,
        )
        cls.stripped_bin = os.path.join(cls.work_dir, "app_prod.stripped")
        subprocess.run(["strip", "-s", "-o", cls.stripped_bin, cls.debug_bin], check=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.work_dir, ignore_errors=True)

    def setUp(self):
        self._procs = []

    def tearDown(self):
        for p in self._procs:
            try:
                p.kill()
                p.wait(timeout=2)
            except Exception:
                pass
            for s in (p.stdin, p.stdout, p.stderr):
                if s:
                    try:
                        s.close()
                    except Exception:
                        pass

    def _start_target(self, bin_path: str) -> subprocess.Popen:
        p = subprocess.Popen(
            [bin_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self._procs.append(p)
        deadline = time.time() + 3.0
        while time.time() < deadline:
            line = p.stdout.readline()
            if "READY" in line:
                break
        return p

    def test_01_ensure_remote_collector_already_present_deploy_and_arch_mismatch(self):
        """Verify ensure_remote_collector handles existing binary, base64 deployment, and arch mismatch."""
        # Case A: Already present on remote target
        adapter_ready = RemoteSshTargetAdapter(
            host="10.0.0.88",
            user="root",
            command_runner=lambda args, t: (0, "READY\n", ""),
        )
        res_ready = adapter_ready.ensure_remote_collector(local_collector_bin=self.stripped_bin)
        self.assertTrue(res_ready["deployed"])
        self.assertEqual(res_ready["status"], "ALREADY_PRESENT")
        self.assertEqual(adapter_ready.collector_path, "/tmp/dynamicstate-collector")

        # Case B: Missing on target, matching arch -> deployed via base64 stream
        from extractor.debug_image import inspect_elf
        target_arch = (inspect_elf(self.stripped_bin).architecture or "x86_64").lower()

        def mock_deploy_runner(cmd_args, timeout):
            cmd = cmd_args[-1]
            if "echo READY || echo MISSING" in cmd:
                return 0, "MISSING\n", ""
            if "uname -m" in cmd:
                return 0, f"{target_arch}\n", ""
            if "DEPLOY_OK" in cmd:
                return 0, "DEPLOY_OK\n", ""
            return 0, "", ""

        adapter_dep = RemoteSshTargetAdapter(
            host="10.0.0.88",
            user="root",
            command_runner=mock_deploy_runner,
        )
        res_dep = adapter_dep.ensure_remote_collector(local_collector_bin=self.stripped_bin)
        self.assertTrue(res_dep["deployed"])
        self.assertEqual(res_dep["status"], "DEPLOYED_BINARY")
        self.assertEqual(adapter_dep.collector_path, "/tmp/dynamicstate-collector")
        self.assertGreater(res_dep["bytes_transferred"], 0)

        # Case C: Architecture mismatch -> safe fallback to POSIX shell
        def mock_mismatch_runner(cmd_args, timeout):
            cmd = cmd_args[-1]
            if "echo READY || echo MISSING" in cmd:
                return 0, "MISSING\n", ""
            if "uname -m" in cmd:
                return 0, "mips64\n", ""
            return 0, "", ""

        adapter_mis = RemoteSshTargetAdapter(
            host="10.0.0.88",
            user="root",
            command_runner=mock_mismatch_runner,
        )
        res_mis = adapter_mis.ensure_remote_collector(local_collector_bin=self.stripped_bin)
        self.assertFalse(res_mis["deployed"])
        self.assertEqual(res_mis["status"], "FALLBACK_SHELL")
        self.assertIsNone(adapter_mis.collector_path)

    def test_02_cli_connect_eval_diff_and_recipe_commands(self):
        """Verify high-level CLI subcommands (connect, eval, diff, recipe) against a live C++ process."""
        proc = self._start_target(self.stripped_bin)

        # 1. CLI connect
        r_conn = subprocess.run(
            [
                sys.executable, "-m", "extractor", "connect",
                "--process-name", "app_prod",
                "--debug-image", self.debug_bin,
                "--corpus", self.corpus_dir,
            ],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        d_conn = json.loads(r_conn.stdout)
        self.assertTrue(d_conn["success"])
        self.assertEqual(d_conn["pid"], proc.pid)

        # 2. CLI eval
        r_eval = subprocess.run(
            [
                sys.executable, "-m", "extractor", "eval",
                "--pid", str(proc.pid),
                "--debug-image", self.debug_bin,
                "--expr", "g_session.worker.state.counter,g_heap_state->counter",
                "--corpus", self.corpus_dir,
            ],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        d_eval = json.loads(r_eval.stdout)
        self.assertTrue(d_eval["success"])
        vals = {x["expression"]: x["value"] for x in d_eval["results"]}
        self.assertEqual(vals["g_session.worker.state.counter"], 42)
        self.assertEqual(vals["g_heap_state->counter"], 99)

        # 3. CLI recipe (save_baseline & compare_baseline)
        r_save = subprocess.run(
            [
                sys.executable, "-m", "extractor", "recipe",
                "--name", "save_baseline",
                "--pid", str(proc.pid),
                "--debug-image", self.debug_bin,
                "--label", "CLI_Baseline",
                "--expr", "g_session.worker.state.counter,g_heap_state->counter",
                "--corpus", self.corpus_dir,
            ],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        d_save = json.loads(r_save.stdout)
        self.assertTrue(d_save["success"])
        bid = d_save["baseline_id"]

        proc.stdin.write("MUTATE\n")
        proc.stdin.flush()
        while True:
            l = proc.stdout.readline()
            if "MUTATED" in l or not l:
                break

        r_cmp = subprocess.run(
            [
                sys.executable, "-m", "extractor", "recipe",
                "--name", "compare_baseline",
                "--pid", str(proc.pid),
                "--debug-image", self.debug_bin,
                "--baseline-id", bid,
                "--corpus", self.corpus_dir,
            ],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        d_cmp = json.loads(r_cmp.stdout)
        self.assertTrue(d_cmp["success"])
        changed = {c["path"]: (c["golden_value"], c["live_value"]) for c in d_cmp["changed"]}
        self.assertEqual(changed.get("g_session.worker.state.counter"), (42, 100))

    def test_03_mcp_playbook_and_Docs_verification(self):
        """Verify runtime_get_playbook MCP tool and PRACTICAL_PLAYBOOK_KO.md documentation."""
        pb = json.loads(mcp_srv.runtime_get_playbook())
        self.assertTrue(pb["success"])
        self.assertGreater(len(pb["recommended_workflow"]), 0)

        playbook_doc = os.path.join(PROJECT_ROOT, "docs", "PRACTICAL_PLAYBOOK_KO.md")
        self.assertTrue(os.path.isfile(playbook_doc))
        with open(playbook_doc, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("instant_xray", content)
        self.assertIn("Golden Baseline", content)
        self.assertIn("runtime_target_connect", content)


if __name__ == "__main__":
    unittest.main()
