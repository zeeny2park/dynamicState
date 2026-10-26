"""Standalone launcher for the Minimalist Process Trace Workspace UI (Production Service).

Keeps the legacy Web UI (`extractor.web.__main__` / `./bin/dynamic-state-ui`) 100% intact
while serving the conversational Process Trace & Memory Pool Workspace on its own port
(default: 18088) connected directly to live local or remote processes.
"""

import argparse
import os
import sys
from typing import List, Optional

from extractor.agent_runtime import AgentRuntime
from extractor.web.server import run_server, run_server_loop



def get_workspace_static_dir() -> str:
    """Returns the absolute path to the Minimalist Process Trace Workspace static UI folder."""
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "workspace_static")


def build_workspace_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dynamic-state-workspace",
        description="Launch the dynamicState Minimalist Process Trace Workspace Web Service (Production)",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=18088, help="Bind port (default: 18088)")
    parser.add_argument(
        "--corpus",
        "--snapshot-dir",
        dest="corpus",
        default="./corpus",
        help="State corpus / snapshot storage directory (default: ./corpus)",
    )
    parser.add_argument(
        "--pid",
        type=int,
        default=None,
        help="Optional target PID to pre-bind on startup",
    )
    parser.add_argument(
        "--process-name",
        default=None,
        help="Optional target process name to auto-discover and pre-bind on startup",
    )
    parser.add_argument(
        "--debug-image",
        "--companion-elf",
        dest="debug_image",
        default=None,
        help="Optional unstripped companion ELF path (if omitted, auto-discovers /proc/<pid>/exe)",
    )
    parser.add_argument(
        "--remote-host",
        default=None,
        help="Optional remote SSH host IP or hostname",
    )
    parser.add_argument(
        "--ssh-user",
        default=None,
        help="Optional SSH username for remote host",
    )
    parser.add_argument(
        "--ssh-port",
        type=int,
        default=22,
        help="SSH port for remote host (default: 22)",
    )
    parser.add_argument(
        "--ssh-key",
        default=None,
        help="Optional SSH private key path",
    )
    parser.add_argument(
        "--ssh-proxy-jump",
        default=None,
        help="Optional SSH ProxyJump bastion host",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_workspace_arg_parser()
    args = parser.parse_args(argv)

    corpus_dir = os.path.abspath(args.corpus)
    os.makedirs(corpus_dir, exist_ok=True)
    runtime = AgentRuntime(corpus_dir=corpus_dir)

    workspace_static_dir = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "workspace_static",
    )

    server = run_server(
        runtime=runtime,
        host=args.host,
        port=args.port,
        static_dir=workspace_static_dir,
    )

    if args.pid or args.process_name or args.debug_image:
        try:
            ctx = server.adapter.watch_manager.bind_target_context(
                pid=args.pid,
                companion_elf_path=args.debug_image,
                process_name=args.process_name,
                remote_host=args.remote_host,
                ssh_user=args.ssh_user,
                ssh_port=args.ssh_port,
                ssh_key=args.ssh_key,
                ssh_proxy_jump=args.ssh_proxy_jump,
            )
            print(
                f"[dynamicState Workspace] Pre-bound active target: PID={ctx.get('pid')} "
                f"ELF={ctx.get('companion_elf_path')} (Host={ctx.get('remote_host') or 'localhost'})"
            )
        except Exception as exc:
            print(f"[dynamicState Workspace] Warning: initial target bind deferred ({exc})", file=sys.stderr)

    actual_port = server.server_address[1]
    print(f"[dynamicState Trace Workspace] Listening on http://{args.host}:{actual_port}")
    print(f"[dynamicState Trace Workspace] Serving production UI from {workspace_static_dir}")
    print("[dynamicState Trace Workspace] Legacy Web UI remains available via ./bin/dynamic-state-ui")
    sys.stdout.flush()

    try:
        run_server_loop(server)
    finally:
        print("\n[dynamicState Trace Workspace] Shutting down...")
    return 0


if __name__ == "__main__":
    sys.exit(main())
