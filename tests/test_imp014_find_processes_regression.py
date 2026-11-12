"""IMP-014 regression: RemoteSshTargetAdapter.find_processes built a remote script containing a raw NUL
byte (Python '\\000') and a raw newline inside tr arguments, so every call died with "embedded null byte"
before reaching the target (found on the QEMU ARM32/BusyBox guests; independent of architecture)."""
import os
import shlex
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from extractor.target_adapter import RemoteSshTargetAdapter  # noqa: E402


class TestFindProcessesScript(unittest.TestCase):
    def _captured_script(self):
        seen = []

        def runner(args, timeout, input_bytes=None):
            seen.append(args)
            return 0, "", ""

        RemoteSshTargetAdapter(host="h", command_runner=runner).find_processes("x")
        self.assertEqual(len(seen), 1)
        return seen[0][-1]

    def test_command_has_no_nul_and_survives_argv(self):
        cmd = self._captured_script()
        self.assertNotIn("\x00", cmd)  # a NUL cannot be passed as an argv element
        subprocess.run(["true", cmd], check=True)

    def test_script_runs_locally_and_lists_this_process(self):
        cmd = self._captured_script()
        inner = shlex.split(cmd)[-1]  # sh -c <script>
        out = subprocess.run(["sh", "-c", inner], capture_output=True, text=True).stdout
        pids = [l.split("|", 1)[0] for l in out.splitlines()]
        self.assertIn(str(os.getpid()), pids)
        line = [l for l in out.splitlines() if l.startswith(f"{os.getpid()}|")][0]
        self.assertNotIn("\n", line.split("|")[1])

    def test_find_processes_parses_output(self):
        out = "12|memtarget|/tmp/memtarget|/tmp/memtarget \n13|sh|/bin/busybox|sh\n"
        ad = RemoteSshTargetAdapter(host="h", command_runner=lambda a, t, input_bytes=None: (0, out, ""))
        r = ad.find_processes("memtarget")
        self.assertEqual([p["pid"] for p in r], [12])


if __name__ == "__main__":
    unittest.main()
