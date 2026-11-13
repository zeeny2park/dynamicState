#!/usr/bin/env bash
# Installs the package into a fresh venv and runs the commands documented in README.md.
#
# Every ```bash block of README.md is executed, in order, in one shell with the venv on PATH, from the repo root,
# except blocks directly preceded by an HTML comment `<!-- check: skip (reason) -->`. Skipped blocks that cannot run
# unattended (blocking servers, a remote target, the full test suite) are checked here by a narrower equivalent.
# Also checked: the MCP JSON config block parses and its command starts a server that answers `initialize`.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
cleanup() { pkill -f /tmp/deadlock_demo 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT

cd "$REPO"
echo "== fresh venv + pip install . =="
python3 -m venv "$WORK/venv" || { rm -rf "$WORK/venv"; python3 -m virtualenv "$WORK/venv"; }  # fallback for hosts without ensurepip
# shellcheck disable=SC1091
. "$WORK/venv/bin/activate"
python3 -m pip install --quiet --upgrade pip
python3 -m pip install --quiet .
(cd "$WORK" && python3 -m extractor.cli --help > /dev/null && dynamic-state --help > /dev/null)
(cd "$WORK" && python3 -c "import extractor.agent_skill as a; print(a.skill_path())")

echo "== README bash blocks =="
python3 - "$REPO/README.md" "$WORK/readme_blocks.sh" <<'PY'
import re, sys
text = open(sys.argv[1], encoding="utf-8").read()
out, n, skipped = ["set -euo pipefail"], 0, 0
for m in re.finditer(r"(<!--\s*check:\s*skip[^>]*-->\s*\n)?```bash\n(.*?)```", text, re.S):
    if m.group(1):
        skipped += 1
        continue
    n += 1
    out.append(f"echo '--- README block {n} ---'")
    out.append(m.group(2))
open(sys.argv[2], "w").write("\n".join(out) + "\n")
print(f"{n} blocks run, {skipped} skipped")
PY
bash "$WORK/readme_blocks.sh"

echo "== skipped blocks: narrower checks =="
dynamic-state connect --help | grep -q -- "--auto-deploy-collector"
dynamic-state server --help | grep -q -- "--allow-mutation"

echo "== agent skill: install from the installed package, every command it names exists =="
dynamic-state skill install --dir "$WORK/skills"
test -f "$WORK/skills/diagnose-process/SKILL.md"
test -f "$WORK/skills/diagnose-process/MANUAL_SCENARIOS.md"
(mkdir "$WORK/proj" && cd "$WORK/proj" && dynamic-state skill install --project && test -f .claude/skills/diagnose-process/SKILL.md)
! dynamic-state skill install --dir "$WORK/skills" 2> /dev/null   # refuses to overwrite
dynamic-state skill install --dir "$WORK/skills" --force
dynamic-state skill show | grep -q "dynamic-state diagnose"
dynamic-state skill show --transport mcp | grep -q "runtime_diagnose_process"
python3 - "$WORK/skills/diagnose-process/SKILL.md" <<'PY'
import re, subprocess, sys
text = open(sys.argv[1], encoding="utf-8").read()
assert text.startswith("---\nname: diagnose-process\n"), "installed skill has no frontmatter"
subs = set()
for span in re.findall(r"`(dynamic-state [^`]+)`", text):
    m = re.match(r"dynamic-state ([a-z][a-z-]*)(?: (install|path|show))?", span)
    if m:
        subs.add(tuple(x for x in m.groups() if x))
assert len(subs) >= 8, subs
for sub in sorted(subs):
    subprocess.run(["dynamic-state", *sub, "--help"], check=True, capture_output=True)
print("skill commands exist:", ", ".join(" ".join(s) for s in sorted(subs)))
PY

python3 - "$REPO/README.md" <<'PY'
import json, re, shutil, subprocess, sys
text = open(sys.argv[1], encoding="utf-8").read()
cfg = None
for m in re.finditer(r"```json\n(.*?)```", text, re.S):
    d = json.loads(m.group(1))
    if "mcpServers" in d:
        cfg = d["mcpServers"]["dynamicstate"]
assert cfg, "README has no mcpServers config block"
exe = shutil.which(cfg["command"])
assert exe, f"MCP config command {cfg['command']!r} is not on PATH after install"
req = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
    "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "readme-check", "version": "0"}}})
r = subprocess.run([exe] + cfg.get("args", []), input=req + "\n", capture_output=True, text=True, timeout=60)
resp = json.loads(r.stdout.splitlines()[0])
assert resp["result"]["serverInfo"]["name"] == "dynamicstate", resp
assert "runtime_diagnose_process" in resp["result"]["instructions"], "instructions are missing the skill text"
print("MCP server answers initialize with the skill as instructions")
PY

python3 -m tests.support.fixture_process -- dynamic-state-workspace --host 127.0.0.1 --port 18765 --corpus "$WORK/corpus" > "$WORK/ws.log" 2>&1 &
WS=$!
for _ in $(seq 1 20); do
    code=$(python3 - <<'PY'
import urllib.request
try:
    print(urllib.request.urlopen("http://127.0.0.1:18765/legacy/workspace", timeout=2).status)
except Exception:
    print(0)
PY
)
    [ "$code" = "200" ] && break
    sleep 0.5
done
kill "$WS" 2>/dev/null || true
[ "$code" = "200" ] || { echo "workspace did not serve /legacy/workspace"; cat "$WORK/ws.log"; exit 1; }
echo "workspace served /legacy/workspace"

echo "README commands OK"
