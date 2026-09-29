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
        self.assertEqual(cp.backend.upper(), "RESTART")
        self.assertEqual(cp.scope, "MULTITHREAD")
        self.assertEqual(cp.restore_semantics, "RESTART_TO_OBSERVATION_POINT")
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

    def test_restore_conditions_observation_point_not_reached(self):
        class MockFrame:
            def __init__(self, name="observation_checkpoint"):
                self._name = name
            def name(self):
                return self._name
            def find_sal(self):
                return None
            def pc(self):
                return 0x1234

        class MockGdb:
            def __init__(self):
                self.commands = []
                self.current_func = "observation_checkpoint"
            def execute(self, cmd, to_string=False):
                self.commands.append(cmd)
                return ""
            def selected_frame(self):
                return MockFrame(self.current_func)

        gdb = MockGdb()
        restorer = RestartBasedRestorer(gdb, breakpoint_spec="observation_checkpoint")
        cp = restorer.checkpoint("C001")
        # Simulate inferior stopping at unexpected function on restore
        gdb.current_func = "unexpected_function"
        with self.assertRaisesRegex(RuntimeError, "RESTORE_OBSERVATION_POINT_NOT_REACHED"):
            restorer.restore(cp)

    def test_restore_conditions_thread_count_mismatch(self):
        class MockThread:
            def is_stopped(self):
                return True

        class MockInferior:
            def __init__(self, count):
                self._count = count
            def threads(self):
                return [MockThread() for _ in range(self._count)]

        class MockFrame:
            def name(self):
                return "observation_checkpoint"
            def find_sal(self):
                return None
            def pc(self):
                return 0x1234

        class MockGdb:
            def __init__(self):
                self.inferior_threads = 4
            def execute(self, cmd, to_string=False):
                return ""
            def selected_inferior(self):
                return MockInferior(self.inferior_threads)
            def selected_thread(self):
                return MockThread()
            def selected_frame(self):
                return MockFrame()

        gdb = MockGdb()
        restorer = RestartBasedRestorer(gdb, breakpoint_spec="observation_checkpoint")
        cp = restorer.checkpoint("C001")
        self.assertEqual(cp.metadata["expected_thread_count"], 4)

        gdb.inferior_threads = 2
        with self.assertRaisesRegex(RuntimeError, "RESTORE_THREAD_COUNT_MISMATCH"):
            restorer.restore(cp)

    def test_state_explorer_determinism_safe_policy_abort(self):
        class NondetController(RuntimeController):
            def __init__(self):
                self.restorer = MockStateRestorer(simulated_nondeterminism=True)
            def checkpoint(self, checkpoint_id=None):
                cp = self.restorer.checkpoint(checkpoint_id)
                cp.backend = "RESTART"
                return cp
            def restore(self, checkpoint):
                self.restorer.restore(checkpoint)
            def release_checkpoint(self, checkpoint):
                self.restorer.release(checkpoint)
            def verify_restart_determinism(self, checkpoint=None):
                return self.restorer.verify_restart_determinism(checkpoint)
            def observe(self):
                from extractor.runtime_state import RuntimeState, ExecutionState, PersistentState
                return RuntimeState(schema_version="0.2", process={"pid": 123}, execution=ExecutionState([]), objects=[], persistent=PersistentState([], []))
            def snapshot(self):
                return self.observe()
            def get_capabilities(self):
                return {
                    "checkpoint": True,
                    "threads": 4,
                    "branch_isolation": {"status": "SUPPORTED", "scope": "MULTITHREAD", "restore_backend": "RESTART"}
                }

        ctrl = NondetController()
        tmp_corpus = tempfile.mkdtemp()
        try:
            explorer = StateExplorer(ctrl, corpus_dir=tmp_corpus, determinism_policy="safe")
            res = explorer.run(max_steps=5)
            self.assertEqual(res["status"], "UNAVAILABLE")
            self.assertEqual(res["reason_code"], "NON_DETERMINISTIC_RUNTIME_STATE")
            self.assertIn("Restart determinism verification failed", res["message"])
        finally:
            shutil.rmtree(tmp_corpus, ignore_errors=True)

    def test_agent_runtime_verify_restart_determinism_action(self):
        class DetController(RuntimeController):
            def __init__(self):
                self.restorer = MockStateRestorer()
            def checkpoint(self, checkpoint_id=None):
                return self.restorer.checkpoint(checkpoint_id)
            def restore(self, checkpoint):
                self.restorer.restore(checkpoint)
            def verify_restart_determinism(self, checkpoint=None):
                return self.restorer.verify_restart_determinism(checkpoint)

        ctrl = DetController()
        runtime = AgentRuntime(controller=ctrl)
        res = runtime.dispatch_action({"action": "VERIFY_RESTART_DETERMINISM"})
        self.assertTrue(res.success)
        self.assertEqual(res.action, "VERIFY_RESTART_DETERMINISM")
        self.assertEqual(res.data["status"], "VERIFIED")


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

    def test_05_parent_a_restore_b_restore_state_hash(self):
        """Verify Requirement 7: Parent -> Branch A -> Restore -> Branch B -> Restore with State Hash equality."""
        py_script = f"""
import sys
sys.path.insert(0, '{self.repo_root}')
import gdb
from extractor.state_restorer import RestartBasedRestorer
from extractor.execution import GdbBackend
from extractor.state_hash import compute_state_hash

gdb.execute('file {self.target_bin}')
gdb.execute('break observation_checkpoint')
gdb.execute('run')

backend = GdbBackend(gdb)
restorer = RestartBasedRestorer(gdb, breakpoint_spec='observation_checkpoint')

# 1. INITIAL PARENT STATE
cp = restorer.checkpoint('PARENT_C001')
s_parent = backend.snapshot()
h_parent = compute_state_hash(s_parent)

# Checkpoint initial values
s0 = gdb.parse_and_eval('g_state')
assert int(s0['counter']) == 10
assert int(s0['mode']) == 1
sess0 = gdb.parse_and_eval('g_session')
assert int(sess0['retry']) == 2

# 2. SIBLING BRANCH A
gdb.execute('set var g_state.counter = 50')
gdb.execute('set var g_session->retry = 10')
gdb.execute('continue')

s_branch_a = backend.snapshot()
h_branch_a = compute_state_hash(s_branch_a)
sa = gdb.parse_and_eval('g_state')
assert int(sa['counter']) == 50
assert int(sa['mode']) == 2
assert bool(sa['flag']) == True
sessa = gdb.parse_and_eval('g_session')
assert int(sessa['retry']) == 10

# 3. RESTORE TO PARENT (R1)
restorer.restore(cp)
s_r1 = backend.snapshot()
h_r1 = compute_state_hash(s_r1)
sr1 = gdb.parse_and_eval('g_state')
assert int(sr1['counter']) == 10
assert int(sr1['mode']) == 1
assert bool(sr1['flag']) == False
sessr1 = gdb.parse_and_eval('g_session')
assert int(sessr1['retry']) == 2

# 4. SIBLING BRANCH B
gdb.execute('set var g_state.counter = -5')
gdb.execute('set var g_session->retry = 0')
gdb.execute('continue')

s_branch_b = backend.snapshot()
h_branch_b = compute_state_hash(s_branch_b)
sb = gdb.parse_and_eval('g_state')
assert int(sb['counter']) == -5
assert int(sb['mode']) == 3
assert bool(sb['flag']) == False
sessb = gdb.parse_and_eval('g_session')
assert int(sessb['retry']) == 0

# 5. RESTORE TO PARENT (R2)
restorer.restore(cp)
s_r2 = backend.snapshot()
h_r2 = compute_state_hash(s_r2)
sr2 = gdb.parse_and_eval('g_state')
assert int(sr2['counter']) == 10
assert int(sr2['mode']) == 1
assert bool(sr2['flag']) == False
sessr2 = gdb.parse_and_eval('g_session')
assert int(sessr2['retry']) == 2

# 6. FINAL STATE HASH AXIOMS
assert h_parent == h_r1, f"hash(Parent) {{h_parent}} != hash(R1) {{h_r1}}"
assert h_parent == h_r2, f"hash(Parent) {{h_parent}} != hash(R2) {{h_r2}}"
assert h_branch_a != h_parent, "hash(A) must not equal hash(Parent)"
assert h_branch_b != h_parent, "hash(B) must not equal hash(Parent)"
assert h_branch_a != h_branch_b, "hash(A) must not equal hash(B)"

print("REQUIREMENT_7_PARENT_A_RESTORE_B_RESTORE_PASS")
"""
        res = subprocess.run(
            ["gdb", "-batch", "-ex", f"python\n{py_script}\n"],
            capture_output=True,
            text=True
        )
        self.assertEqual(res.returncode, 0, f"GDB test failed:\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}")
        self.assertIn("REQUIREMENT_7_PARENT_A_RESTORE_B_RESTORE_PASS", res.stdout)

    def test_06_timeout_isolation_on_multithreaded_target(self):
        """Verify Requirement 9: Timeout branch isolation under multithreaded execution."""
        py_script = f"""
import sys
sys.path.insert(0, '{self.repo_root}')
import gdb
import time
import os
import signal
import threading
from extractor.state_restorer import RestartBasedRestorer

gdb.execute('file {self.target_bin}')
gdb.execute('break observation_checkpoint')
gdb.execute('run')

restorer = RestartBasedRestorer(gdb, breakpoint_spec='observation_checkpoint')
cp = restorer.checkpoint('PARENT_TIMEOUT')

# Branch A: trigger intentional infinite loop (state = 255)
gdb.execute('set var g_state.state = 255')

def interrupt_inferior():
    time.sleep(0.3)
    try:
        inf = gdb.selected_inferior()
        if inf.pid:
            os.kill(inf.pid, signal.SIGINT)
    except Exception:
        pass

t = threading.Thread(target=interrupt_inferior)
t.start()
try:
    gdb.execute('continue')
except Exception:
    pass
t.join()

# Restore after TIMEOUT interruption
restorer.restore(cp)
sr = gdb.parse_and_eval('g_state')
assert int(sr['counter']) == 10
assert int(sr['state']) == 1
assert int(sr['mode']) == 1

# Execute Branch B after timeout recovery
gdb.execute('set var g_state.counter = 50')
gdb.execute('continue')
s_b = gdb.parse_and_eval('g_state')
assert int(s_b['counter']) == 50
assert int(s_b['state']) == 2
assert int(s_b['mode']) == 2

print("REQUIREMENT_9_TIMEOUT_ISOLATION_PASS")
"""
        res = subprocess.run(
            ["gdb", "-batch", "-ex", f"python\n{py_script}\n"],
            capture_output=True,
            text=True
        )
        self.assertEqual(res.returncode, 0, f"GDB timeout isolation failed:\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}")
        self.assertIn("REQUIREMENT_9_TIMEOUT_ISOLATION_PASS", res.stdout)

    def test_07_thread_lifecycle_isolation(self):
        """Verify Requirement 10: Thread creation (Case A) and worker termination (Case B) isolation."""
        py_script = f"""
import sys
sys.path.insert(0, '{self.repo_root}')
import gdb
from extractor.state_restorer import RestartBasedRestorer

gdb.execute('file {self.target_bin}')
gdb.execute('break observation_checkpoint')
gdb.execute('run')

inf = gdb.selected_inferior()
assert len(inf.threads()) == 4

restorer = RestartBasedRestorer(gdb, breakpoint_spec='observation_checkpoint')
cp = restorer.checkpoint('PARENT_LIFECYCLE')

# Case A: Spawn 4th worker thread (state = 500) -> threads become 5
gdb.execute('set var g_state.state = 500')
gdb.execute('continue')
assert len(inf.threads()) == 5, f"Expected 5 threads, got {{len(inf.threads())}}"

# Restore to pristine parent state (threads must return to 4)
restorer.restore(cp)
assert len(inf.threads()) == 4, f"Expected 4 threads after restore, got {{len(inf.threads())}}"

# Case B: Terminate worker 3 (state = 600) -> threads become 3
gdb.execute('set var g_state.state = 600')
gdb.execute('continue')
assert len(inf.threads()) == 3, f"Expected 3 threads, got {{len(inf.threads())}}"

# Restore to pristine parent state (threads must return to 4)
restorer.restore(cp)
assert len(inf.threads()) == 4, f"Expected 4 threads after restore, got {{len(inf.threads())}}"

print("REQUIREMENT_10_THREAD_LIFECYCLE_ISOLATION_PASS")
"""
        res = subprocess.run(
            ["gdb", "-batch", "-ex", f"python\n{py_script}\n"],
            capture_output=True,
            text=True
        )
        self.assertEqual(res.returncode, 0, f"GDB lifecycle isolation failed:\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}")
        self.assertIn("REQUIREMENT_10_THREAD_LIFECYCLE_ISOLATION_PASS", res.stdout)

    def test_08_tls_determinism_across_threads(self):
        """Verify Requirement 11: Thread-Local Storage (TLS) values reproduced across restarts."""
        py_script = f"""
import sys
sys.path.insert(0, '{self.repo_root}')
import gdb
from extractor.state_restorer import RestartBasedRestorer

gdb.execute('file {self.target_bin}')
gdb.execute('break observation_checkpoint')
gdb.execute('run')

restorer = RestartBasedRestorer(gdb, breakpoint_spec='observation_checkpoint')
cp = restorer.checkpoint('PARENT_TLS')

tls_before = restorer.verify_tls_determinism()
assert tls_before['status'] == 'VERIFIED', f"TLS status was {{tls_before['status']}}"
assert tls_before['threads'] == 4

vals_before = [t['t_worker_counter'] for t in tls_before['tls_values'].values()]
assert 0 in vals_before and 101 in vals_before and 202 in vals_before and 303 in vals_before

gdb.execute('set var g_state.counter = 50')
gdb.execute('continue')

restorer.restore(cp)
tls_after = restorer.verify_tls_determinism()
assert tls_after['status'] == 'VERIFIED'
assert tls_after['threads'] == 4

vals_after = [t['t_worker_counter'] for t in tls_after['tls_values'].values()]
assert 0 in vals_after and 101 in vals_after and 202 in vals_after and 303 in vals_after

print("REQUIREMENT_11_TLS_DETERMINISM_PASS")
"""
        res = subprocess.run(
            ["gdb", "-batch", "-ex", f"python\n{py_script}\n"],
            capture_output=True,
            text=True
        )
        self.assertEqual(res.returncode, 0, f"GDB TLS determinism failed:\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}")
        self.assertIn("REQUIREMENT_11_TLS_DETERMINISM_PASS", res.stdout)

    def test_09_nondeterministic_workload_classification(self):
        """Verify Requirement 12: Nondeterministic workload classified as NON_DETERMINISTIC without engine crash."""
        nondet_src = os.path.join(self.repo_root, "examples", "sample_multithread_nondet.cpp")
        nondet_bin = os.path.join(self.repo_root, "examples", "sample_multithread_nondet")
        comp = subprocess.run(
            ["g++", "-g", "-O0", "-pthread", nondet_src, "-o", nondet_bin],
            capture_output=True,
            text=True
        )
        self.assertEqual(comp.returncode, 0)

        py_script = f"""
import sys
sys.path.insert(0, '{self.repo_root}')
import gdb
from extractor.state_restorer import RestartBasedRestorer

gdb.execute('file {nondet_bin}')
gdb.execute('break observation_checkpoint')
gdb.execute('run')

restorer = RestartBasedRestorer(gdb, breakpoint_spec='observation_checkpoint')
cp = restorer.checkpoint('PARENT_NONDET')
det = restorer.verify_restart_determinism(cp)

assert det['deterministic'] == False
assert det['status'] == 'NON_DETERMINISTIC'
assert det['reason'] == 'NON_DETERMINISTIC_RUNTIME_STATE'
assert det['parent_state_hash'] != det['restored_state_hash']

print("REQUIREMENT_12_NONDETERMINISTIC_CLASSIFICATION_PASS")
"""
        res = subprocess.run(
            ["gdb", "-batch", "-ex", f"python\n{py_script}\n"],
            capture_output=True,
            text=True
        )
        self.assertEqual(res.returncode, 0, f"GDB nondeterministic workload failed:\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}")
        self.assertIn("REQUIREMENT_12_NONDETERMINISTIC_CLASSIFICATION_PASS", res.stdout)


if __name__ == "__main__":
    unittest.main()
