"""Multithread Checkpoint/Restore & Autonomous Exploration Integration Tests.

Validates:
1. Root cause verification: GDB fork checkpoint refusal on multithreaded inferiors.
2. RestartBasedRestorer branch isolation across sibling mutations on multithreaded target.
3. Crash and timeout isolation under multithreaded execution.
4. Structured capability reporting and safe alternatives recommendation.
5. GDB 9.2 compatibility for multithreaded branch isolation.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from extractor.agent_runtime import AgentRuntime
from extractor.explorer import StateExplorer
from extractor.runtime_controller import (
    GdbRuntimeController,
    RuntimeCapabilities,
    RuntimeController,
)
from extractor.state_restorer import (
    AdaptiveGdbRestorer,
    GdbCheckpointRestorer,
    MockStateRestorer,
    NullRestorer,
    RestartBasedRestorer,
    create_restorer,
)


class MultithreadUnitTests(unittest.TestCase):
    """Unit tests for multithread capability checks and restorer routing."""

    def test_gdb_checkpoint_restorer_multithread_refusal(self):
        class MockThread:
            def is_stopped(self):
                return True

        class MockInferior:
            def threads(self):
                return [MockThread(), MockThread(), MockThread(), MockThread()]

        class MockGdb:
            def selected_thread(self):
                return MockThread()

            def selected_inferior(self):
                return MockInferior()

            def execute(self, cmd, to_string=False):
                if cmd == "checkpoint":
                    raise RuntimeError("checkpoint: can't checkpoint multiple threads.")
                return ""

        gdb = MockGdb()
        restorer = GdbCheckpointRestorer(gdb)

        # Single thread capability
        cap1 = restorer.get_capability(1)
        self.assertTrue(cap1["supported"])
        self.assertEqual(cap1["scope"], "SINGLE_THREAD_ONLY")
        self.assertIsNone(cap1["reason"])

        # Multithread capability
        cap4 = restorer.get_capability(4)
        self.assertFalse(cap4["supported"])
        self.assertEqual(cap4["scope"], "SINGLE_THREAD_ONLY")
        self.assertIn("cannot checkpoint multiple threads", cap4["reason"])

        # Checkpoint call must raise MULTITHREAD_CHECKPOINT_UNSUPPORTED
        with self.assertRaisesRegex(RuntimeError, "MULTITHREAD_CHECKPOINT_UNSUPPORTED"):
            restorer.checkpoint("C001")

    def test_restart_based_restorer_capabilities(self):
        class MockGdb:
            def __init__(self):
                self.commands = []

            def execute(self, cmd, to_string=False):
                self.commands.append(cmd)
                return ""

        gdb = MockGdb()
        restorer = RestartBasedRestorer(gdb, breakpoint_spec="observation_checkpoint")

        cap = restorer.get_capability(4)
        self.assertTrue(cap["supported"])
        self.assertEqual(cap["backend"], "RESTART")
        self.assertEqual(cap["scope"], "MULTITHREAD")
        self.assertEqual(cap["threads"], 4)

        cp = restorer.checkpoint("CP_TEST")
        self.assertEqual(cp.checkpoint_id, "CP_TEST")
        self.assertEqual(cp.backend, "restart")
        self.assertIn("break observation_checkpoint", gdb.commands)

        restorer.restore(cp)
        self.assertIn("run", gdb.commands)

    def test_null_restorer_behavior(self):
        restorer = NullRestorer(reason="Target is attached and multithreaded.")
        cap = restorer.get_capability(4)
        self.assertFalse(cap["supported"])
        self.assertEqual(cap["scope"], "NONE")

        with self.assertRaisesRegex(RuntimeError, "CHECKPOINT_UNSUPPORTED"):
            restorer.checkpoint()

        with self.assertRaisesRegex(RuntimeError, "RESTORE_UNSUPPORTED"):
            restorer.restore(None)

    def test_adaptive_restorer_routing(self):
        class MockThread:
            pass

        class MockInferior:
            def __init__(self, count):
                self._count = count

            def threads(self):
                return [MockThread() for _ in range(self._count)]

        class DummyController:
            def __init__(self, thread_count=1, is_attached=False):
                self.is_attached = is_attached
                self.thread_count = thread_count

            class gdb:
                @staticmethod
                def selected_inferior():
                    return MockInferior(controller.thread_count)

                @staticmethod
                def execute(cmd, to_string=False):
                    return ""

        controller = DummyController(thread_count=1, is_attached=False)
        adaptive = AdaptiveGdbRestorer(controller, breakpoint_spec="observation_checkpoint")

        # 1 thread launched -> GDB fork checkpoint
        cap1 = adaptive.get_capability(1)
        self.assertTrue(cap1["supported"])
        self.assertEqual(cap1["backend"], "GDB_CHECKPOINT")

        # 4 threads launched -> RESTART restorer
        controller.thread_count = 4
        cap4 = adaptive.get_capability(4)
        self.assertTrue(cap4["supported"])
        self.assertEqual(cap4["backend"], "RESTART")

        # 4 threads attached -> NullRestorer (UNAVAILABLE)
        controller.is_attached = True
        cap_att = adaptive.get_capability(4)
        self.assertFalse(cap_att["supported"])
        self.assertEqual(cap_att["backend"], "NONE")
        self.assertEqual(cap_att["scope"], "NONE")

    def test_state_explorer_unsupported_branch_isolation(self):
        class UnsupportedController(RuntimeController):
            def get_capabilities(self):
                return {
                    "checkpoint": False,
                    "restore": False,
                    "threads": 4,
                    "branch_isolation": {
                        "status": "UNAVAILABLE",
                        "scope": "NONE",
                        "restore_backend": "NONE",
                        "threads": 4,
                        "reason": "Multithreaded attached inferior cannot fork or restart.",
                        "safe_alternatives": ["OBSERVE", "SNAPSHOT", "INSPECT_OBJECT"]
                    }
                }

            def observe(self):
                return None

            def snapshot(self):
                return None

        ctrl = UnsupportedController()
        tmp_corpus = tempfile.mkdtemp()
        try:
            explorer = StateExplorer(ctrl, corpus_dir=tmp_corpus)
            res = explorer.run(max_steps=5)
            self.assertEqual(res["status"], "UNAVAILABLE")
            self.assertEqual(res["reason_code"], "MULTITHREAD_BRANCH_ISOLATION_UNSUPPORTED")
            self.assertEqual(res["threads"], 4)
            self.assertIn("SNAPSHOT", res["safe_alternatives"])

            # Test AgentRuntime wrapping
            runtime = AgentRuntime(controller=ctrl, corpus_dir=tmp_corpus)
            agent_res = runtime.explore(max_steps=5)
            self.assertFalse(agent_res.success)
            self.assertEqual(agent_res.error.code, "MULTITHREAD_BRANCH_ISOLATION_UNSUPPORTED")
            self.assertEqual(agent_res.data["status"], "UNAVAILABLE")
        finally:
            shutil.rmtree(tmp_corpus, ignore_errors=True)


class MultithreadGdbIntegrationTests(unittest.TestCase):
    """Integration tests running against real GDB and multithreaded C++ target."""

    @classmethod
    def setUpClass(cls):
        cls.repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        cls.target_src = os.path.join(cls.repo_root, "examples", "sample_multithread.cpp")
        cls.target_bin = os.path.join(cls.repo_root, "examples", "sample_multithread")

        # Compile multithreaded sample target
        comp = subprocess.run(
            ["g++", "-g", "-O0", "-pthread", cls.target_src, "-o", cls.target_bin],
            capture_output=True,
            text=True
        )
        if comp.returncode != 0:
            raise RuntimeError(f"Failed to build sample_multithread: {comp.stderr}")

    def test_01_gdb_checkpoint_refusal_on_multithread_inferior(self):
        """Verify that native GDB built-in checkpoint explicitly rejects multithreaded processes."""
        res = subprocess.run(
            [
                "gdb", "-batch",
                "-ex", f"file {self.target_bin}",
                "-ex", "break observation_checkpoint",
                "-ex", "run",
                "-ex", "checkpoint",
            ],
            capture_output=True,
            text=True
        )
        # GDB must fail checkpoint command with error message
        self.assertNotEqual(res.returncode, 0)
        combined = res.stdout + res.stderr
        self.assertIn("checkpoint: can't checkpoint multiple threads.", combined)

    def test_02_restart_based_branch_isolation_and_independence(self):
        """Verify RestartBasedRestorer preserves clean branch isolation across sibling mutations."""
        py_script = f"""
import sys
sys.path.insert(0, '{self.repo_root}')
import gdb
from extractor.state_restorer import RestartBasedRestorer

gdb.execute('file {self.target_bin}')
gdb.execute('break observation_checkpoint')
gdb.execute('run')

inf = gdb.selected_inferior()
assert len(inf.threads()) == 4, f"Expected 4 threads, got {{len(inf.threads())}}"

restorer = RestartBasedRestorer(gdb, breakpoint_spec='observation_checkpoint')
cp = restorer.checkpoint('PARENT_STATE')

# Verify initial parent state
s0 = gdb.parse_and_eval('g_state')
assert int(s0['counter']) == 10
assert int(s0['state']) == 1
assert bool(s0['flag']) == False

# Sibling Branch 1: mutate counter = 50 -> continue -> state=2, flag=true
gdb.execute('set var g_state.counter = 50')
gdb.execute('continue')
s1 = gdb.parse_and_eval('g_state')
assert int(s1['counter']) == 50
assert int(s1['state']) == 2
assert bool(s1['flag']) == True

# Restore to pristine parent state
restorer.restore(cp)
sr1 = gdb.parse_and_eval('g_state')
assert int(sr1['counter']) == 10, f"Expected counter=10, got {{int(sr1['counter'])}}"
assert int(sr1['state']) == 1, f"Expected state=1, got {{int(sr1['state'])}}"
assert bool(sr1['flag']) == False
assert len(inf.threads()) == 4

# Sibling Branch 2: mutate counter = -5 -> continue -> state=0, flag=false
gdb.execute('set var g_state.counter = -5')
gdb.execute('continue')
s2 = gdb.parse_and_eval('g_state')
assert int(s2['counter']) == -5
assert int(s2['state']) == 0
assert bool(s2['flag']) == False

# Restore to pristine parent state (zero leakage from Branch 1 or Branch 2)
restorer.restore(cp)
sr2 = gdb.parse_and_eval('g_state')
assert int(sr2['counter']) == 10
assert int(sr2['state']) == 1
assert bool(sr2['flag']) == False
assert len(inf.threads()) == 4

print("MULTITHREAD_BRANCH_INDEPENDENCE_SUCCESS")
"""
        res = subprocess.run(
            ["gdb", "-batch", "-ex", f"python\n{py_script}\n"],
            capture_output=True,
            text=True
        )
        self.assertEqual(res.returncode, 0, f"GDB test failed:\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}")
        self.assertIn("MULTITHREAD_BRANCH_INDEPENDENCE_SUCCESS", res.stdout)

    def test_03_crash_isolation_on_multithreaded_target(self):
        """Verify that an inferior crash (SIGSEGV) is cleanly recovered without state leakage."""
        py_script = f"""
import sys
sys.path.insert(0, '{self.repo_root}')
import gdb
from extractor.state_restorer import RestartBasedRestorer

gdb.execute('file {self.target_bin}')
gdb.execute('break observation_checkpoint')
gdb.execute('run')

restorer = RestartBasedRestorer(gdb, breakpoint_spec='observation_checkpoint')
cp = restorer.checkpoint('PARENT')

# Trigger deliberate crash (SIGSEGV)
gdb.execute('set var g_state.state = 139')
try:
    gdb.execute('continue')
except Exception:
    pass

# Restore after crash
restorer.restore(cp)
sr = gdb.parse_and_eval('g_state')
assert int(sr['counter']) == 10
assert int(sr['state']) == 1
assert bool(sr['flag']) == False

inf = gdb.selected_inferior()
assert len(inf.threads()) == 4

print("MULTITHREAD_CRASH_ISOLATION_SUCCESS")
"""
        res = subprocess.run(
            ["gdb", "-batch", "-ex", f"python\n{py_script}\n"],
            capture_output=True,
            text=True
        )
        self.assertEqual(res.returncode, 0, f"GDB crash recovery failed:\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}")
        self.assertIn("MULTITHREAD_CRASH_ISOLATION_SUCCESS", res.stdout)

    def test_04_gdb92_container_multithread_branch_isolation(self):
        """Verify multithread branch isolation in GDB 9.2 Docker container if available."""
        # Check docker
        docker_check = subprocess.run(
            ["docker", "image", "inspect", "dynamicstate-gdb92:latest"],
            capture_output=True,
            text=True
        )
        if docker_check.returncode != 0:
            self.skipTest("dynamicstate-gdb92:latest Docker image not available.")

        cmd = [
            "docker", "run", "--rm",
            "-v", f"{self.repo_root}:/workspace",
            "-w", "/workspace",
            "dynamicstate-gdb92:latest",
            "bash", "-c",
            """
g++ -g -O0 -pthread examples/sample_multithread.cpp -o /tmp/sample_mt
gdb -batch -ex 'file /tmp/sample_mt' -ex 'break observation_checkpoint' -ex 'run' -ex "python
import sys
sys.path.insert(0, '/workspace')
import gdb
from extractor.state_restorer import RestartBasedRestorer

inf = gdb.selected_inferior()
assert len(inf.threads()) == 4
restorer = RestartBasedRestorer(gdb, breakpoint_spec='observation_checkpoint')
cp = restorer.checkpoint('PARENT')

# Branch 1
gdb.execute('set var g_state.counter = 50')
gdb.execute('continue')
s1 = gdb.parse_and_eval('g_state')
assert int(s1['counter']) == 50
assert int(s1['state']) == 2

# Restore
restorer.restore(cp)
sr1 = gdb.parse_and_eval('g_state')
assert int(sr1['counter']) == 10
assert int(sr1['state']) == 1

# Branch 2 Crash
gdb.execute('set var g_state.state = 139')
try:
    gdb.execute('continue')
except Exception:
    pass

# Restore after crash
restorer.restore(cp)
sr2 = gdb.parse_and_eval('g_state')
assert int(sr2['counter']) == 10
assert int(sr2['state']) == 1
assert len(inf.threads()) == 4

print('DOCKER_GDB92_MULTITHREAD_PASS')
"
"""
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"GDB 9.2 multithread test failed:\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}")
        self.assertIn("DOCKER_GDB92_MULTITHREAD_PASS", res.stdout)


if __name__ == "__main__":
    unittest.main()
