"""IMP-022 (packaging, missing-mcp exit) and IMP-023 (agent skill, playbook/instructions single source)."""

import importlib.util
import inspect
import json
import os
import subprocess
import sys
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

from extractor.agent_skill import parse_skill, skill_body, skill_path, workflow_steps  # noqa: E402

DEMO_SYMBOLS = ("gpMem", "g_corrupt_record", "g_ipc_ring", "g_task_list", "g_session", "g_service", "g_cache")


def _load_server():
    spec = importlib.util.spec_from_file_location("mcp_server_under_test", os.path.join(ROOT, "scripts", "mcp_server.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestSkillFile(unittest.TestCase):
    def test_skill_exists_with_valid_frontmatter(self):
        path = os.path.join(ROOT, "skills", "diagnose-process", "SKILL.md")
        self.assertTrue(os.path.isfile(path))
        self.assertEqual(os.path.normpath(skill_path()), os.path.normpath(path))
        with open(path, encoding="utf-8") as fh:
            meta, body = parse_skill(fh.read())
        self.assertEqual(meta.get("name"), "diagnose-process")
        self.assertGreater(len(meta.get("description", "")), 80)
        self.assertIn("runtime_diagnose_process", meta["description"])
        for needle in ("INCONCLUSIVE", "not_covered", "collection_impact", "explicit approval",
                       "runtime_heap_owner_lookup", "runtime_heap_leak_candidates"):
            self.assertIn(needle, body)

    def test_skill_never_names_demo_symbols(self):
        body = skill_body()
        for sym in DEMO_SYMBOLS:
            self.assertNotIn(sym, body)

    def test_manual_scenarios_documented(self):
        p = os.path.join(ROOT, "skills", "diagnose-process", "MANUAL_SCENARIOS.md")
        self.assertTrue(os.path.isfile(p))
        txt = open(p, encoding="utf-8").read()
        for needle in ("deadlock", "healthy", "debug ELF"):
            self.assertIn(needle, txt)


class TestServerSingleSource(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = _load_server()

    def test_instructions_are_the_skill_body(self):
        self.assertEqual(self.srv.server.instructions, skill_body())

    def test_playbook_is_the_skill(self):
        pb = json.loads(self.srv.runtime_get_playbook())
        self.assertTrue(pb["success"])
        self.assertEqual(pb["playbook"], skill_body())
        self.assertEqual(pb["recommended_workflow"], workflow_steps())
        self.assertGreater(len(pb["recommended_workflow"]), 0)
        self.assertTrue(any("runtime_diagnose_process" in s for s in pb["recommended_workflow"]))

    def test_no_tool_default_names_a_demo_symbol(self):
        tools = self.srv.server._tool_manager.list_tools()
        self.assertGreater(len(tools), 20)
        for t in tools:
            for name, p in inspect.signature(t.fn).parameters.items():
                d = p.default
                if isinstance(d, str):
                    for sym in DEMO_SYMBOLS:
                        self.assertNotIn(sym, d, f"{t.name}.{name} default {d!r} names demo symbol {sym}")
        for fn_name, param in (("runtime_scan_memory_pool", "base_expression"),
                               ("runtime_smart_compact_query", "query_or_expression"),
                               ("runtime_traverse_linked_structure", "next_field")):
            self.assertEqual(inspect.signature(getattr(self.srv, fn_name)).parameters[param].default, "")

    def test_missing_expression_is_refused_not_defaulted(self):
        for raw in (self.srv.runtime_scan_memory_pool(pid=1), self.srv.runtime_smart_compact_query()):
            res = json.loads(raw)
            self.assertFalse(res["success"])
            self.assertEqual(res["error_code"], "MissingArgument")


class TestMissingMcp(unittest.TestCase):
    def test_server_exits_nonzero_with_install_hint_when_mcp_missing(self):
        code = (
            "import sys, runpy\n"
            "sys.modules['mcp'] = None\n"  # makes `import mcp...` raise ImportError
            f"runpy.run_path({os.path.join(ROOT, 'scripts', 'mcp_server.py')!r}, run_name='__main__')\n"
        )
        r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("pip install", r.stderr)
        self.assertIn("mcp", r.stderr)


class TestPackagingMetadata(unittest.TestCase):
    def test_pyproject_declares_mcp_and_test_extra_consistent_with_requirements(self):
        text = open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8").read()
        self.assertIn('requires-python = ">=3.10"', text)
        self.assertIn('dependencies = ["mcp>=2.0.0,<3"]', text)
        self.assertIn('test = ["PyYAML>=6.0"]', text)
        req = open(os.path.join(ROOT, "requirements-test.txt"), encoding="utf-8").read()
        self.assertIn("mcp>=2.0.0,<3", req)
        self.assertIn("PyYAML>=6.0", req)

    def test_license_file_and_readme_badge(self):
        lic = open(os.path.join(ROOT, "LICENSE"), encoding="utf-8").read()
        self.assertTrue(lic.startswith("MIT License"))
        self.assertIn("Copyright (c) 2026 zeeny2park", lic)
        self.assertIn("(LICENSE)", open(os.path.join(ROOT, "README.md"), encoding="utf-8").read())


if __name__ == "__main__":
    unittest.main()
