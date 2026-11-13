"""Loader for the agent skill (skills/diagnose-process/SKILL.md), the single source of the workflow text.

The MCP server's `instructions` and the `runtime_get_playbook` tool are both generated from this file, so they
cannot drift from the skill. In a source checkout the file is <repo>/skills/diagnose-process/SKILL.md; in an
installed package it is shipped as package data of `dynamicstate_skills`.

One file serves two transports. Lines tagged `[mcp] ` apply when the agent has the MCP tools, lines tagged `[cli] `
when it only has a shell; blocks between `<!-- begin:cli -->` and `<!-- end:cli -->` (or `mcp`) are one transport's
only, and `raw` blocks (the explanation of these tags) appear only in the installed file. The MCP server sends the `mcp` view (the `[cli]` lines and blocks removed, tags stripped), so it never carries
command-line material it cannot use. The installed skill keeps the whole file.
"""

import os
import re
import shutil
from typing import Dict, List, Tuple

SKILL_NAME = "diagnose-process"


TRANSPORTS = ("mcp", "cli")


def skill_path() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(here, "..", "skills", SKILL_NAME, "SKILL.md"),
        os.path.join(here, "..", "dynamicstate_skills", SKILL_NAME, "SKILL.md"),
    ]
    for c in candidates:
        c = os.path.normpath(c)
        if os.path.isfile(c):
            return c
    raise FileNotFoundError("agent skill file not found; looked in: " + ", ".join(os.path.normpath(c) for c in candidates))


def parse_skill(text: str) -> Tuple[Dict[str, str], str]:
    """Split YAML frontmatter (flat `key: value` lines) from the body."""
    if not text.startswith("---\n"):
        raise ValueError("SKILL.md must start with YAML frontmatter")
    end = text.find("\n---\n", 4)
    if end < 0:
        raise ValueError("SKILL.md frontmatter is not terminated")
    meta: Dict[str, str] = {}
    for line in text[4:end].splitlines():
        if ":" in line and not line.startswith(" "):
            k, v = line.split(":", 1)
            meta[k.strip()] = v.strip()
    return meta, text[end + 5:].lstrip("\n")


def load_skill() -> Tuple[Dict[str, str], str]:
    with open(skill_path(), "r", encoding="utf-8") as fh:
        return parse_skill(fh.read())


def skill_dir() -> str:
    return os.path.dirname(skill_path())


def render_transport(body: str, transport: str) -> str:
    """The body as seen by one transport: the other transport's tagged lines and blocks are dropped, own tags stripped.
    `transport="all"` returns the body unchanged."""
    if transport == "all":
        return body
    if transport not in TRANSPORTS:
        raise ValueError(f"transport must be one of {TRANSPORTS} or 'all', got {transport!r}")
    other = [t for t in TRANSPORTS if t != transport]
    out: List[str] = []
    skipping = False
    for line in body.splitlines():
        m = re.match(r"\s*<!-- (begin|end):(\w+) -->\s*$", line)
        if m:
            if m.group(2) == transport:
                continue                      # own block: keep content, drop the marker lines
            if m.group(2) not in TRANSPORTS + ("raw",):
                raise ValueError(f"unknown block marker {line.strip()!r}")
            skipping = m.group(1) == "begin"
            continue
        if skipping:
            continue
        stripped = line.lstrip()
        if any(stripped.startswith(f"[{t}] ") for t in other):
            continue
        for t in (transport,):
            if stripped.startswith(f"[{t}] "):
                line = line[: len(line) - len(stripped)] + stripped[len(t) + 3:]
        out.append(line)
    text = re.sub(r"\n{3,}", "\n\n", "\n".join(out))
    return text + ("\n" if body.endswith("\n") else "")


def skill_body(transport: str = "mcp") -> str:
    """The skill text for a transport (default: what the MCP server sends as its instructions)."""
    return render_transport(load_skill()[1], transport)


def install_skill(base_dir: str, force: bool = False) -> str:
    """Copy the skill directory to <base_dir>/<SKILL_NAME>; returns the destination."""
    dest = os.path.join(base_dir, SKILL_NAME)
    if os.path.exists(dest):
        if not force:
            raise FileExistsError(f"{dest} already exists")
        shutil.rmtree(dest)
    os.makedirs(base_dir, exist_ok=True)
    shutil.copytree(skill_dir(), dest, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    return dest


def workflow_steps(body: str = "") -> List[str]:
    """The numbered lines of the '## Workflow' section."""
    body = body or skill_body()
    out: List[str] = []
    on = False
    for line in body.splitlines():
        if line.startswith("## "):
            on = line.strip() == "## Workflow"
            continue
        if on and line.strip():
            out.append(line.rstrip())
    return out
