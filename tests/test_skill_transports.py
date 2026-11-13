"""The diagnose-process skill serves two transports (MCP tool calls, plain shell commands) from ONE file.

This test keeps them from drifting apart:
- every `[mcp]` line is immediately followed by its `[cli]` twin (and the reverse);
- every MCP tool named in the skill is a registered tool and its keyword arguments are real parameters;
- every `dynamic-state <command>` named in the skill exists and every option named with it is in its `--help`;
- the pairing of workflow step -> MCP tool -> CLI command is pinned (WORKFLOW_MAP), so adding or removing a step on
  one side fails here;
- the MCP view carries no command-line material, the CLI view no MCP material;
- the commands run against live fixtures and print the documented shape; `skill install` copies the skill.
"""

import importlib.util
import inspect
import json
import os
import re
import select
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

from extractor.agent_skill import parse_skill, render_transport, skill_body, skill_dir, skill_path  # noqa: E402
from tests.support.fixture_process import fixture_popen  # noqa: E402

with open(skill_path(), encoding="utf-8") as _fh:
    RAW = _fh.read()
META, BODY = parse_skill(RAW)

# workflow step -> (MCP tool, CLI subcommand). The skill must name exactly these pairs, in this order of appearance
# not required, but every pair must appear as an adjacent [mcp]/[cli] line pair.
WORKFLOW_MAP = {
    "find the pid by name": ("runtime_target_connect", "find-process"),
    "diagnose (symptom, structured symptom, remote, language)": ("runtime_diagnose_process", "diagnose"),
    "export the report (md / html / json)": ("runtime_export_incident_report", "export-report"),
    "thread call stacks and locks": ("runtime_inspect_thread_callstack_and_locks", "callstacks"),
    "heap leak candidates": ("runtime_heap_leak_candidates", "heap-leaks"),
    "heap owner lookup": ("runtime_heap_owner_lookup", "heap-owner"),
    "evaluate a variable": ("runtime_eval_memory_path", "eval"),
    "find a symbol": ("runtime_symbol_search", "fuzzy-resolve"),
}


def _load_server():
    spec = importlib.util.spec_from_file_location("mcp_server_skill_transports", os.path.join(ROOT, "scripts", "mcp_server.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _tagged_runs(text):
    """Runs of consecutive tagged lines: [[('mcp', line), ('cli', line), ...], ...]."""
    runs, cur = [], []
    for line in text.splitlines():
        m = re.match(r"\s*\[(mcp|cli)\] (.*)", line)
        if m:
            cur.append((m.group(1), m.group(2)))
        elif cur:
            runs.append(cur)
            cur = []
    if cur:
        runs.append(cur)
    return runs


def _spans(line):
    return re.findall(r"`([^`]+)`", line)


_HELP = {}


def _help(*sub):
    key = " ".join(sub)
    if key not in _HELP:
        r = subprocess.run([sys.executable, "-m", "extractor.cli", *sub, "--help"], cwd=ROOT, capture_output=True, text=True, timeout=60)
        _HELP[key] = (r.returncode, r.stdout + r.stderr)
    return _HELP[key]


def _flags(span):
    return re.findall(r"(?<![\w-])(--?[A-Za-z][\w-]*)", span)


def _has_flag(help_text, flag):
    return re.search(r"(?<![\w-])" + re.escape(flag) + r"(?![\w-])", help_text) is not None


class TestSkillStructure(unittest.TestCase):
    def test_frontmatter_installs_as_is(self):
        self.assertTrue(RAW.startswith("---\n"))
        self.assertEqual(META["name"], os.path.basename(skill_dir()))
        desc = META["description"]
        self.assertGreater(len(desc), 120)
        self.assertIn("runtime_diagnose_process", desc)
        self.assertIn("dynamic-state", desc)
        self.assertTrue(os.path.isfile(os.path.join(skill_dir(), "SKILL.md")))

    def test_every_mcp_line_has_its_cli_twin(self):
        runs = _tagged_runs(BODY)
        self.assertGreaterEqual(len(runs), 8)
        for run in runs:
            tags = [t for t, _ in run]
            self.assertEqual(tags, ["mcp", "cli"] * (len(tags) // 2), f"unpaired transport lines: {run}")

    def test_workflow_map_matches_the_skill(self):
        found = set()
        for run in _tagged_runs(BODY):
            for (_, mcp), (_, cli) in zip(run[0::2], run[1::2]):
                tools = list(dict.fromkeys(re.findall(r"\bruntime_\w+", mcp)))
                subs = list(dict.fromkeys(re.findall(r"dynamic-state ([a-z][a-z-]*)", cli)))
                if tools and subs:
                    self.assertEqual(len(tools), len(subs), f"a pair names {tools} on the MCP side but {subs} on the command line")
                    found.update(zip(tools, subs))
        expected = set(WORKFLOW_MAP.values())
        missing = expected - found
        self.assertFalse(missing, f"workflow steps without both forms in the skill: {missing}")
        # the diagnose step is introduced by the intro pair; everything else must be in the map
        extra = {p for p in found if p not in expected}
        self.assertFalse(extra, f"transport pairs in the skill that WORKFLOW_MAP does not list: {extra}")

    def test_views_do_not_leak_the_other_transport(self):
        mcp, cli = skill_body("mcp"), skill_body("cli")
        for view in (mcp, cli):
            self.assertNotIn("[mcp]", view)
            self.assertNotIn("[cli]", view)
            self.assertNotIn("begin:", view)
        self.assertNotIn("dynamic-state", mcp)
        self.assertNotIn("runtime_", cli)
        self.assertIn("runtime_diagnose_process", mcp)
        self.assertIn("dynamic-state diagnose", cli)
        self.assertIn("Before you start", cli)
        self.assertNotIn("Before you start", mcp)
        # the raw install keeps both, and says how the tags work
        self.assertIn("[mcp]", BODY)
        self.assertIn("[cli]", BODY)
        self.assertEqual(render_transport(BODY, "all"), BODY)

    def test_untagged_text_is_shared_by_both_views(self):
        shared, in_block = [], False
        for l in BODY.splitlines():
            m = re.match(r"\s*<!-- (begin|end):(\w+) -->", l)
            if m:
                in_block = m.group(1) == "begin"
            elif l.strip() and not in_block and not re.match(r"\s*\[(mcp|cli)\] ", l):
                shared.append(l)
        for transport in ("mcp", "cli"):
            view = skill_body(transport)
            for l in shared:
                if "dynamic-state" in l or "runtime_" in l:
                    continue
                self.assertIn(l, view)


class TestNamedMembersExist(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = _load_server()
        cls.tools = {t.name: t for t in cls.srv.server._tool_manager.list_tools()}

    def test_every_runtime_name_is_a_registered_tool_with_real_parameters(self):
        named = set(re.findall(r"\bruntime_\w+", RAW))
        self.assertTrue(named)
        for name in named:
            self.assertIn(name, self.tools, f"skill names MCP tool {name} that the server does not register")
        for run in _tagged_runs(BODY):
            for tag, line in run:
                if tag != "mcp":
                    continue
                for span in _spans(line):
                    m = re.match(r"(runtime_\w+)\((.*)\)$", span)
                    if not m:
                        continue
                    params = set(inspect.signature(self.tools[m.group(1)].fn).parameters)
                    inner = re.sub(r"\[[^\]]*\]", lambda mm: mm.group(0), m.group(2))
                    for part in re.split(r"[,\[\]]", inner):
                        arg = part.strip().split("=")[0].strip()
                        if arg:
                            self.assertIn(arg, params, f"{m.group(1)} has no parameter {arg!r} (in `{span}`)")

    def test_structured_symptom_fields_are_real_diagnose_parameters(self):
        params = set(inspect.signature(self.tools["runtime_diagnose_process"].fn).parameters)
        for field in ("symptom_kind", "symptom_frequency", "symptom_duration", "affected_area", "related_objects",
                      "remote_host", "ssh_user", "ssh_port", "ssh_key", "ssh_proxy_jump", "auto_deploy_collector", "language"):
            self.assertIn(field, params)
            self.assertIn(field, RAW)

    def test_every_dynamic_state_command_and_option_exists(self):
        cmd_spans = []
        for run in _tagged_runs(BODY):
            for tag, line in run:
                if tag == "cli":
                    cmd_spans.extend(_spans(line))
        for line in BODY.splitlines():
            if not re.match(r"\s*\[(mcp|cli)\] ", line):
                cmd_spans.extend(s for s in _spans(line) if s.startswith("dynamic-state "))
        subs_used, union_help = set(), ""
        for span in cmd_spans:
            m = re.match(r"dynamic-state ([a-z][a-z-]*)(?: (install|path))?", span)
            if not m:
                continue
            sub = (m.group(1), m.group(2)) if m.group(2) else (m.group(1),)
            rc, text = _help(*sub)
            self.assertEqual(rc, 0, f"`dynamic-state {' '.join(sub)} --help` failed: {span}")
            subs_used.add(sub)
            union_help += text
            for flag in _flags(span):
                self.assertTrue(_has_flag(text, flag), f"{flag} is not an option of `dynamic-state {' '.join(sub)}` (in `{span}`)")
        # option lists written without the command (e.g. `--symptom-kind KIND`) must exist in some command used here
        for span in cmd_spans:
            if span.startswith("dynamic-state "):
                continue
            for flag in _flags(span):
                self.assertTrue(_has_flag(union_help, flag), f"{flag} (in `{span}`) is an option of none of the commands named in the skill")
        for _, cli in WORKFLOW_MAP.values():
            self.assertIn((cli,), subs_used)

    def test_install_command_in_skill_is_the_real_one(self):
        r = subprocess.run(["git", "ls-files", "pyproject.toml", "target/collector/Makefile"], cwd=ROOT, capture_output=True, text=True)
        self.assertIn("pyproject.toml", r.stdout)
        self.assertIn("python3 -m pip install .", BODY)
        self.assertIn("https://github.com/zeeny2park/dynamicState.git", BODY)
        with open(os.path.join(ROOT, "pyproject.toml")) as fh:
            self.assertIn("dynamic-state-mcp", fh.read())

    def test_server_sends_the_mcp_view_only(self):
        self.assertEqual(self.srv.server.instructions, skill_body("mcp"))
        self.assertNotIn("dynamic-state ", self.srv.server.instructions)


class TestSkillInstallCommand(unittest.TestCase):
    def _run(self, *args, cwd=None, home=None):
        env = dict(os.environ, PYTHONPATH=ROOT)
        if home:
            env["HOME"] = home
        return subprocess.run([sys.executable, "-m", "extractor.cli", "skill", *args], cwd=cwd or ROOT, env=env,
                              capture_output=True, text=True, timeout=60)

    def test_install_dir_force_project_and_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = os.path.join(tmp, "skills")
            r = self._run("install", "--dir", base)
            self.assertEqual(r.returncode, 0, r.stderr)
            dest = os.path.join(base, "diagnose-process")
            with open(os.path.join(dest, "SKILL.md")) as fh:
                self.assertEqual(fh.read(), RAW)
            self.assertTrue(os.path.isfile(os.path.join(dest, "MANUAL_SCENARIOS.md")))
            again = self._run("install", "--dir", base)
            self.assertEqual(again.returncode, 1)
            self.assertIn("--force", again.stderr)
            open(os.path.join(dest, "stale.txt"), "w").close()
            self.assertEqual(self._run("install", "--dir", base, "--force").returncode, 0)
            self.assertFalse(os.path.exists(os.path.join(dest, "stale.txt")))
            proj = os.path.join(tmp, "proj")
            os.mkdir(proj)
            self.assertEqual(self._run("install", "--project", cwd=proj).returncode, 0)
            self.assertTrue(os.path.isfile(os.path.join(proj, ".claude", "skills", "diagnose-process", "SKILL.md")))
            home = os.path.join(tmp, "home")
            os.mkdir(home)
            self.assertEqual(self._run("install", home=home).returncode, 0)
            self.assertTrue(os.path.isfile(os.path.join(home, ".claude", "skills", "diagnose-process", "SKILL.md")))
            p = self._run("path")
            self.assertEqual(p.stdout.strip(), skill_dir())
            self.assertEqual(self._run("show").stdout, skill_body("cli"))
            self.assertEqual(self._run("show", "--transport", "mcp").stdout, skill_body("mcp"))

    def test_pyproject_ships_every_skill_file(self):
        with open(os.path.join(ROOT, "pyproject.toml")) as fh:
            self.assertIn('dynamicstate_skills = ["*/SKILL.md", "*/*.md"]', fh.read())


def _cc(src, out, *extra):
    r = subprocess.run(["gcc", "-g", "-O0", "-pthread", "-o", out, src, *extra], capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        raise unittest.SkipTest("gcc failed: " + r.stderr[-300:])


def _start(binary, wait_ready):
    proc = fixture_popen([binary], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    lines, buf, deadline = [], b"", time.monotonic() + 60
    while wait_ready:
        left = deadline - time.monotonic()
        if left <= 0:
            proc.kill()
            raise AssertionError("fixture did not print READY")
        if not select.select([proc.stdout], [], [], left)[0]:
            continue
        chunk = os.read(proc.stdout.fileno(), 65536)
        if not chunk:
            raise AssertionError("fixture exited before READY")
        buf += chunk
        done = False
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            lines.append(line.decode().strip())
            done = done or lines[-1] == "READY"
        if done:
            break
    if not wait_ready:
        time.sleep(1.5)
    return proc, lines


@unittest.skipUnless(shutil.which("gcc") and shutil.which("readelf"), "needs gcc and readelf")
class TestSkillCommandsAgainstLiveFixtures(unittest.TestCase):
    """Runs the command-line steps of the skill and checks the documented result shape."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="skill_cli_")
        cls.corpus = os.path.join(cls.tmp, "corpus")
        cls.dl_elf = os.path.join(cls.tmp, "deadlock_demo")
        cls.heap_elf = os.path.join(cls.tmp, "heap_demo")
        _cc(os.path.join(ROOT, "benchmarks", "diagnosis_accuracy", "targets", "deadlock_pipeline.c"), cls.dl_elf)
        _cc(os.path.join(ROOT, "tests", "fixtures", "real_runtime", "proc_heap_ownership.c"), cls.heap_elf)
        cls.dl, _ = _start(cls.dl_elf, wait_ready=False)
        cls.heap, cls.heap_lines = _start(cls.heap_elf, wait_ready=True)
        cls.env = dict(os.environ, PYTHONPATH=ROOT)

    @classmethod
    def tearDownClass(cls):
        for p in (cls.dl, cls.heap):
            p.kill_tree()
            for s in (p.stdout,):
                if s:
                    s.close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def cli(self, *args, ok=(0,)):
        r = subprocess.run([sys.executable, "-m", "extractor.cli", *args], cwd=self.tmp, env=self.env,
                           capture_output=True, text=True, timeout=240)
        self.assertIn(r.returncode, ok, r.stderr[-800:] + r.stdout[-300:])
        return r

    def test_find_process_lists_the_fixture(self):
        d = json.loads(self.cli("find-process", "deadlock_demo", "-d", self.dl_elf).stdout)
        self.assertTrue(d["success"])
        hit = [m for m in d["matches"] if m["pid"] == self.dl.pid]
        self.assertEqual(len(hit), 1)
        for key in ("pid", "name", "executable", "cmdline", "build_id_match"):
            self.assertIn(key, hit[0])
        self.assertTrue(hit[0]["build_id_match"])
        none = self.cli("find-process", "no_such_process_xyz_123", ok=(1,))
        self.assertFalse(json.loads(none.stdout)["matches"])

    def test_diagnose_json_has_the_documented_fields_and_report_export_works(self):
        r = self.cli("diagnose", "-p", str(self.dl.pid), "--lang", "en", "--corpus", self.corpus, "--json",
                     "--symptom-kind", "hang_deadlock")
        d = json.loads(r.stdout)
        for key in ("verdict", "findings", "not_covered", "collection_impact", "healthy_scope", "human_summary", "report_path"):
            self.assertIn(key, d)
        self.assertEqual(d["verdict"], "CONFIRMED_FAULT")
        self.assertTrue(d["collection_impact"]["zero_stop"])
        self.assertTrue(d["findings"][0]["subjects"])
        self.assertTrue(os.path.isfile(d["report_path"]))
        md, html, js = (os.path.join(self.tmp, n) for n in ("report.md", "report.html", "report.json"))
        e = json.loads(self.cli("export-report", "-p", str(self.dl.pid), "-d", f"/proc/{self.dl.pid}/exe", "--corpus", self.corpus,
                                "--lang", "en", "-o", md, "--report-html", html, "--report-json", js).stdout)
        self.assertEqual(e["verdict"], "CONFIRMED_FAULT")
        for key in ("saved_path", "saved_html_path", "saved_json_path"):
            self.assertIn(key, e)
        with open(md) as fh:
            self.assertIn("deadlock", fh.read().lower())
        with open(html) as fh:
            self.assertIn("<html", fh.read().lower())
        with open(js) as fh:
            self.assertIn("section_e_findings_and_root_cause", json.load(fh))

    def test_unreadable_and_missing_pid_are_inconclusive_not_errors(self):
        for pid in ("999999", "1"):
            d = json.loads(self.cli("diagnose", "-p", pid, "--corpus", self.corpus, "--json").stdout)
            self.assertEqual(d["verdict"], "INCONCLUSIVE")
            self.assertEqual(d["not_covered"][0]["kind"], "target_unreadable")

    def test_callstacks_names_the_lock_cycle(self):
        d = json.loads(self.cli("callstacks", "-p", str(self.dl.pid), "-d", f"/proc/{self.dl.pid}/exe", "--corpus", self.corpus).stdout)
        self.assertTrue(d["success"])
        self.assertIn("m_out", json.dumps(d))

    def test_heap_leaks_and_heap_owner_name_the_owner(self):
        gt = [l.split() for l in self.heap_lines]
        leak = next(f for f in gt if f and f[0] == "LEAK")[1]
        block = next(f for f in gt if f and f[0] == "BLOCK")
        leaks = json.loads(self.cli("heap-leaks", "-p", str(self.heap.pid), "-d", self.heap_elf, "--corpus", self.corpus).stdout)
        self.assertTrue(leaks["success"])
        self.assertGreater(leaks["total_candidates"], 0)
        listed = {ex["user_address"] for c in leaks["by_size_class"] for ex in c["examples"]}
        self.assertIn(hex(int(leak, 16)), listed)
        own = json.loads(self.cli("heap-owner", "-p", str(self.heap.pid), "-d", self.heap_elf, "-a", f"{block[1]},{leak}",
                                  "--corpus", self.corpus).stdout)
        self.assertTrue(own["success"])
        by_addr = {r["address"]: r for r in own["results"]}
        self.assertEqual(by_addr[hex(int(block[1], 16))]["referrers"][0]["path"], block[3])
        self.assertTrue(by_addr[hex(int(leak, 16))]["leak_candidate"])
        # same output shape as the MCP tools
        srv = _load_server()
        mcp_leaks = json.loads(srv.runtime_heap_leak_candidates(pid=self.heap.pid, companion_elf=self.heap_elf))
        self.assertEqual(set(leaks), set(mcp_leaks))
        mcp_own = json.loads(srv.runtime_heap_owner_lookup(addresses=block[1], pid=self.heap.pid, companion_elf=self.heap_elf))
        self.assertEqual(set(own), set(mcp_own))

    def test_heap_commands_report_a_bad_target_as_json_failure(self):
        r = self.cli("heap-leaks", "-p", "999999", "-d", self.heap_elf, "--corpus", self.corpus, ok=(1,))
        self.assertFalse(json.loads(r.stdout)["success"])

    def test_eval_and_fuzzy_resolve_run(self):
        d = json.loads(self.cli("eval", "--pid", str(self.heap.pid), "--debug-image", self.heap_elf, "--expr", "g_list", "--corpus", self.corpus).stdout)
        self.assertTrue(d.get("success", True))
        self.assertIn("g_list", json.dumps(d))
        f = json.loads(self.cli("fuzzy-resolve", "-p", str(self.heap.pid), "-d", self.heap_elf, "-q", "cache", "--corpus", self.corpus).stdout)
        self.assertIn("g_cache", json.dumps(f))


if __name__ == "__main__":
    unittest.main()
