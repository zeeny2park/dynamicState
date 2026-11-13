"""Policy: long-lived fixture processes are started through tests/support/fixture_process.py, never bare.

A bare ``subprocess.Popen`` in tests/benchmarks/scripts/examples is allowed only if listed below with the
reason it needs no containment (a short tool invocation).  Adding a new bare Popen therefore fails this test
until the author either uses ``fixture_popen``/``fixture_process`` or documents why the process is short-lived.
Background jobs in shell scripts (``cmd &``) must go through ``start_fixture`` / the module CLI.
"""
import ast
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY_ROOTS = ("tests", "benchmarks", "scripts", "examples")

# (file, first argument as written) -> reason the direct Popen is legitimate.
ALLOWED_POPEN = {
    ("tests/support/fixture_process.py", "cmd"):
        "the launcher itself: starts its own watchdog (which holds no fixture memory)",
    ("tests/test_fixture_process.py", '[sys.executable, "-c", RUNNER]'):
        "the runner under test: the test kills it on purpose to prove its fixture dies with it",
    ("tests/test_ebpf_integration.py", "probe_cmd"):
        "bpftrace -c <fixture --loop 1>: finite, bounded by communicate(timeout=4) in the same function",
    ("tests/test_imp006_remote_diagnose.py", '["sh", "-c", args[-1]]'):
        "fake ssh transport: runs one short remote command to completion",
    ("tests/test_imp011_remote_thread_info.py", '["sh", "-c", args[-1]]'):
        "fake ssh transport: runs one short remote command to completion",
    ("tests/test_imp020_collection_impact.py", '["sh", "-c", args[-1]]'):
        "fake ssh transport: runs one short remote command to completion",
    ("tests/test_imp021_collector_daemon_channel.py", '["sh", "-c", args[-1]]'):
        "fake ssh transport: runs one short remote command to completion",
    ("tests/test_remote_new_diagnoses.py", '["sh", "-c", args[-1]]'):
        "fake ssh transport: runs one short remote command to completion",
    ("benchmarks/collection_impact_benchmark.py", '["sh", "-c", args[-1]]'):
        "fake ssh transport: runs one short remote command to completion",
    ("tests/test_imp_001_002_003_004_019.py", '["true"]'):
        "exits immediately; used to obtain a pid that is already dead",
    ("tests/test_mcp_first_phase1.py", '["true"]'):
        "exits immediately; used to obtain a pid that is already dead",
    ("tests/test_mcp_runtime_diagnostics.py", '["true"]'):
        "exits immediately; used to obtain a pid that is already dead",
    ("tests/test_phase1_2_4_1_final_trust_boundary_and_serialization_closure.py", '["node", "-e", js_script]'):
        "short tool: one JSON request/response on stdin/stdout, then exits",
    ("scripts/qemu_matrix/guest.py", "inject_ssh_opts(args)"):
        "ssh client streams to the qemu guest; the client is a transport, bounded by the guest session",
}

# multiprocessing workers: short, finite Python work (no allocation loops), joined with timeouts by the tests.
ALLOWED_MULTIPROCESSING = {
    "tests/test_phase2_0_a_3_18_deterministic_multiprocess_barriers.py",
    "tests/test_phase2_0_a_3_19_multiprocess_crash_repaired.py",
}

SHELL_FILES = ("run_all_tests.sh", "scripts", "tests")


def _py_files():
    for top in PY_ROOTS:
        for dp, _dn, fns in os.walk(os.path.join(ROOT, top)):
            if "__pycache__" in dp:
                continue
            for fn in fns:
                if fn.endswith(".py"):
                    yield os.path.join(dp, fn)


def _popen_sites():
    sites = []
    for path in _py_files():
        rel = os.path.relpath(path, ROOT)
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
            if name == "Popen":
                arg = ast.get_source_segment(src, node.args[0]) if node.args else "?"
                sites.append((rel, " ".join((arg or "?").split()), node.lineno))
            elif name in ("fork", "posix_spawn", "posix_spawnp", "spawnl", "spawnv", "spawnvp", "execv", "execvp"):
                if isinstance(fn, ast.Attribute) and getattr(fn.value, "id", "") == "os":
                    sites.append((rel, f"os.{name}", node.lineno))
    return sites


class FixtureLaunchPolicyTests(unittest.TestCase):
    def test_no_bare_popen_outside_the_allowlist(self):
        bad = [f"{rel}:{ln}  Popen({arg})" for rel, arg, ln in _popen_sites() if (rel, arg) not in ALLOWED_POPEN]
        self.assertEqual(bad, [], "start long-lived fixtures with tests.support.fixture_process.fixture_popen / "
                                  "fixture_process (or add a documented entry to ALLOWED_POPEN):\n" + "\n".join(bad))

    def test_allowlist_has_no_stale_entries(self):
        present = {(rel, arg) for rel, arg, _ln in _popen_sites()}
        stale = sorted(k for k in ALLOWED_POPEN if k not in present)
        self.assertEqual(stale, [], "ALLOWED_POPEN entries that no longer exist: " + repr(stale))

    def test_multiprocessing_only_in_allowed_files(self):
        bad = []
        for path in _py_files():
            rel = os.path.relpath(path, ROOT)
            if rel in ALLOWED_MULTIPROCESSING or rel == os.path.relpath(__file__, ROOT):
                continue
            with open(path, encoding="utf-8") as fh:
                if re.search(r"^\s*(import multiprocessing|from multiprocessing)", fh.read(), re.M):
                    bad.append(rel)
        self.assertEqual(bad, [], "multiprocessing children are not contained; use fixture_popen: " + repr(bad))

    def test_shell_background_jobs_use_the_launcher(self):
        bad = []
        files = []
        for entry in SHELL_FILES:
            p = os.path.join(ROOT, entry)
            if os.path.isfile(p):
                files.append(p)
            else:
                files += [os.path.join(p, f) for f in os.listdir(p) if f.endswith(".sh")]
        for path in files:
            with open(path, encoding="utf-8") as fh:
                for n, line in enumerate(fh, 1):
                    if re.search(r"(?<!&)&\s*$", line) and "fixture_process" not in line:
                        bad.append(f"{os.path.relpath(path, ROOT)}:{n}: {line.strip()}")
        self.assertEqual(bad, [], "background `cmd &` must use start_fixture / python3 -m tests.support.fixture_process")

    def test_default_ceiling_and_overrides_are_documented(self):
        from tests.support import fixture_process as fp
        self.assertEqual(fp.DEFAULT_MAX_RSS_MIB, 1536)
        src = open(fp.__file__, encoding="utf-8").read()
        for name in fp.FIXTURE_RSS_OVERRIDES_MIB:
            self.assertRegex(src, r"#.*" + re.escape(name), f"override for {name} needs its measurement in a comment")


if __name__ == "__main__":
    unittest.main()
