import unittest

from extractor.gdb_env import gdb_subprocess_env


class GdbSubprocessEnvTests(unittest.TestCase):
    TC = "/opt/hostedtoolcache/Python/3.10.22/x64"

    def test_toolcache_entries_removed_others_kept(self):
        env = gdb_subprocess_env({
            "LD_LIBRARY_PATH": f"{self.TC}/lib:/usr/local/lib:/opt/hostedtoolcache/Python/3.10.22/x64/lib/",
            "PYTHONHOME": self.TC,
            "PYTHONPATH": f"{self.TC}/lib/python3.10:/work/lib",
            "PATH": f"{self.TC}/bin:/usr/bin",
            "HOME": "/home/x",
        })
        self.assertEqual(env["LD_LIBRARY_PATH"], "/usr/local/lib")
        self.assertNotIn("PYTHONHOME", env)
        self.assertEqual(env["PYTHONPATH"], "/work/lib")
        self.assertEqual(env["PATH"], f"{self.TC}/bin:/usr/bin")
        self.assertEqual(env["HOME"], "/home/x")

    def test_variable_removed_when_only_toolcache_entries(self):
        env = gdb_subprocess_env({"LD_LIBRARY_PATH": f"{self.TC}/lib", "FOO": "1"})
        self.assertNotIn("LD_LIBRARY_PATH", env)
        self.assertEqual(env["FOO"], "1")

    def test_runner_tool_cache_variable_and_non_toolcache_pythonhome(self):
        env = gdb_subprocess_env({
            "RUNNER_TOOL_CACHE": "/custom/cache",
            "LD_LIBRARY_PATH": "/custom/cache/Python/3.10/x64/lib:/usr/lib",
            "PYTHONHOME": "/usr",
        })
        self.assertEqual(env["LD_LIBRARY_PATH"], "/usr/lib")
        self.assertEqual(env["PYTHONHOME"], "/usr")


if __name__ == "__main__":
    unittest.main()
