"""Command-line equivalents of the MCP tools the diagnose-process skill uses, plus `skill install`.

These exist so an agent without MCP can follow the same workflow from a shell (see skills/diagnose-process/SKILL.md).
Each command prints the same JSON object as the MCP tool of the same purpose:

- `find-process`  -> candidates for a process name (the lookup behind `runtime_target_connect(process_name=...)`)
- `heap-owner`    -> `runtime_heap_owner_lookup`
- `heap-leaks`    -> `runtime_heap_leak_candidates`
- `skill install` -> copies the skill directory to where an agent loads skills from; `skill show` prints its text
"""

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional

from .agent_skill import SKILL_NAME, install_skill, skill_body, skill_dir


def _add_remote_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--remote-host", "--host", dest="remote_host", default=None, help="SSH host/IP of a REMOTE target")
    p.add_argument("--ssh-user", "--user", dest="ssh_user", default=None, help="SSH username")
    p.add_argument("--ssh-port", "--port", dest="ssh_port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("--ssh-key", "--identity", dest="ssh_key", default=None, help="SSH private key path")
    p.add_argument("--ssh-proxy-jump", dest="ssh_proxy_jump", default=None, help="Optional SSH ProxyJump")


def add_parsers(subparsers) -> None:
    fp = subparsers.add_parser("find-process", help="List processes whose name matches NAME, to get the PID to diagnose (local or remote)")
    fp.add_argument("name", help="Process name or part of its command line")
    fp.add_argument("-d", "--debug-image", "--companion-elf", dest="debug_image", default=None,
                    help="Only list processes whose GNU build-id matches this ELF")
    fp.add_argument("--limit", type=int, default=50)
    _add_remote_arguments(fp)

    ho = subparsers.add_parser("heap-owner", help="Name the variable that owns a heap address (glibc ptmalloc, zero-stop)")
    ho.add_argument("-p", "--pid", type=int, required=True)
    ho.add_argument("-a", "--addresses", required=True, help="Comma-separated hex or decimal addresses")
    ho.add_argument("-d", "--debug-image", "--companion-elf", dest="debug_image", default=None,
                    help="ELF with DWARF (default: the target's own executable)")
    ho.add_argument("--no-typed-locals", action="store_true", default=False, help="Do not use typed locals as roots")
    ho.add_argument("--max-bytes-read", type=int, default=1073741824)
    ho.add_argument("--max-wall-clock-ms", type=float, default=300000.0)
    ho.add_argument("--corpus", default="corpus")
    _add_remote_arguments(ho)

    hl = subparsers.add_parser("heap-leaks", help="List heap leak candidates: in-use glibc chunks no root reaches (zero-stop)")
    hl.add_argument("-p", "--pid", type=int, required=True)
    hl.add_argument("-d", "--debug-image", "--companion-elf", dest="debug_image", default=None,
                    help="ELF with DWARF (default: the target's own executable)")
    hl.add_argument("--max-examples", type=int, default=8, help="Example addresses per chunk size class")
    hl.add_argument("--no-typed-locals", action="store_true", default=False, help="Do not use typed locals as roots")
    hl.add_argument("--max-bytes-read", type=int, default=1073741824)
    hl.add_argument("--max-wall-clock-ms", type=float, default=300000.0)
    hl.add_argument("--corpus", default="corpus")
    _add_remote_arguments(hl)

    sk = subparsers.add_parser("skill", help="Install or locate the diagnose-process agent skill (for agents without MCP)")
    ss = sk.add_subparsers(dest="skill_command", required=True)
    si = ss.add_parser("install", help="Copy the skill directory so an agent can load it")
    where = si.add_mutually_exclusive_group()
    where.add_argument("--dir", default=None, help="Skills directory to install into (default: ~/.claude/skills)")
    where.add_argument("--project", action="store_true", default=False, help="Install into ./.claude/skills of the current directory")
    si.add_argument("--force", action="store_true", default=False, help="Replace an existing installed copy")
    ss.add_parser("path", help="Print the directory of the skill shipped with this installation")
    sh = ss.add_parser("show", help="Print the skill text without frontmatter, to paste into an agent's standing instructions (default: the command-line view)")
    sh.add_argument("--transport", choices=("cli", "mcp"), default="cli", help="Which calling convention to print (default: cli)")


def _fail(error: str, code: str) -> int:
    print(json.dumps({"success": False, "error": error, "error_code": code}, indent=2, ensure_ascii=False))
    return 1


def _remote_kwargs(args) -> Dict[str, Any]:
    return dict(remote_host=args.remote_host, ssh_user=args.ssh_user, ssh_port=args.ssh_port,
                ssh_key=args.ssh_key, ssh_proxy_jump=args.ssh_proxy_jump)


def _heap_analysis(args):
    from .reachability import analyze_heap_ownership
    from .watch_session import WatchSessionManager
    wm = WatchSessionManager(corpus_dir=os.path.abspath(args.corpus))
    pid, elf = args.pid, args.debug_image
    if elf is None:
        ctx = wm.resolve_target_context(pid=pid, companion_elf_path=None, **_remote_kwargs(args))
        pid, elf = ctx["pid"], ctx["companion_elf_path"]
    adapter = wm._resolve_adapter(pid=pid, **_remote_kwargs(args))
    return analyze_heap_ownership(
        pid=int(pid), companion_elf_path=elf, adapter=adapter, manager=wm,
        include_typed_locals=not args.no_typed_locals,
        budget_limits={"max_bytes_read": int(args.max_bytes_read), "max_wall_clock_ms": float(args.max_wall_clock_ms)},
    )


def run_heap_owner(args) -> int:
    try:
        raw = [a for a in args.addresses.replace(";", ",").split(",") if a.strip()]
        addrs = [int(a.strip(), 0) for a in raw]
        if not addrs:
            return _fail("--addresses needs at least one address", "INVALID_PARAM")
        an = _heap_analysis(args)
        summary = an.summary()
        out = {
            "success": an.ok, "analysis_id": an.analysis_id, "status": an.status, "message": an.message,
            "heap_counts": (summary.get("heap_walk") or {}).get("counts"),
            "arena_location": (summary.get("heap_walk") or {}).get("arena_location"),
            "reachability": summary.get("reachability"), "root_sources": summary.get("root_sources"),
            "cost": summary.get("cost"), "results": [an.lookup(a) for a in addrs],
        }
    except Exception as exc:
        return _fail(str(exc), type(exc).__name__)
    print(json.dumps(out, indent=2, ensure_ascii=False, default=str))
    return 0 if out["success"] else 1


def run_heap_leaks(args) -> int:
    try:
        an = _heap_analysis(args)
        summary = an.summary()
        out = {
            "success": an.ok, "analysis_id": an.analysis_id,
            "heap_counts": (summary.get("heap_walk") or {}).get("counts"),
            "reachability": summary.get("reachability"), "cost": summary.get("cost"),
            **an.leak_report(max_examples_per_class=max(1, int(args.max_examples))),
        }
    except Exception as exc:
        return _fail(str(exc), type(exc).__name__)
    print(json.dumps(out, indent=2, ensure_ascii=False, default=str))
    return 0 if out["success"] else 1


def run_find_process(args) -> int:
    from .watch_session import WatchSessionManager
    try:
        wm = WatchSessionManager(corpus_dir=os.path.abspath(os.path.join(os.getcwd(), "corpus")))
        adapter = wm._resolve_adapter(pid=1, **_remote_kwargs(args))
        build_id: Optional[str] = None
        if args.debug_image:
            from .debug_image import inspect_elf
            build_id = inspect_elf(args.debug_image).build_id
        found = adapter.find_processes(process_name=args.name, companion_build_id=build_id, limit=args.limit + 1)
        # this command's own command line contains the name; it is not a match
        matches: List[Dict[str, Any]] = [m for m in found if m.get("pid") != os.getpid() or adapter.is_remote()][: args.limit]
    except Exception as exc:
        return _fail(str(exc), type(exc).__name__)
    print(json.dumps({"success": True, "name": args.name, "count": len(matches), "matches": matches},
                     indent=2, ensure_ascii=False, default=str))
    return 0 if matches else 1


def run_skill(args) -> int:
    if args.skill_command == "path":
        print(skill_dir())
        return 0
    if args.skill_command == "show":
        sys.stdout.write(skill_body(args.transport))
        return 0
    if args.dir:
        base = os.path.expanduser(args.dir)
    elif args.project:
        base = os.path.join(os.getcwd(), ".claude", "skills")
    else:
        base = os.path.join(os.path.expanduser("~"), ".claude", "skills")
    try:
        dest = install_skill(base, force=args.force)
    except FileExistsError as exc:
        print(f"error: {exc} (use --force to replace it)", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"error: cannot install the skill into {base}: {exc}", file=sys.stderr)
        return 1
    print(f"Installed skill '{SKILL_NAME}' to {dest}")
    return 0


def dispatch(args) -> Optional[int]:
    """Returns an exit code when `args.command` is one of ours, else None."""
    if args.command == "find-process":
        return run_find_process(args)
    if args.command == "heap-owner":
        return run_heap_owner(args)
    if args.command == "heap-leaks":
        return run_heap_leaks(args)
    if args.command == "skill":
        return run_skill(args)
    return None
