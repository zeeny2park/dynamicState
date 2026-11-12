"""Loader for the agent skill (skills/diagnose-process/SKILL.md), the single source of the workflow text.

The MCP server's `instructions` and the `runtime_get_playbook` tool are both generated from this file, so they
cannot drift from the skill. In a source checkout the file is <repo>/skills/diagnose-process/SKILL.md; in an
installed package it is shipped as package data of `dynamicstate_skills`.
"""

import os
from typing import Dict, List, Tuple

SKILL_NAME = "diagnose-process"


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


def skill_body() -> str:
    return load_skill()[1]


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
