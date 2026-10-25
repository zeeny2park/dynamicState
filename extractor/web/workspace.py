"""CLI launcher for the Minimalist Conversational Process Trace Workspace Web UI.

Preserves the existing Web UI (`dynamic-state-ui` / `python3 -m extractor.web`)
while providing a clean Gemini-style chat + progressive process trace workspace
under a dedicated command (`dynamic-state-workspace` or `dynamic-state workspace`).
"""

import argparse
import os
import sys

from extractor.agent_runtime import AgentRuntime
from extractor.web.server import run_server, run_server_loop


def get_workspace_static_dir() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "workspace_static")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="dynamic-state-workspace",
        description="dynamicState: Minimalist Chat + Process Trace Workspace Web UI",
    )
    parser.add_argument("--host", type=str, default="127.0.0.1", help="HTTP host to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080, help="HTTP port to bind (default: 8080)")
    parser.add_argument("--corpus", type=str, default="corpus", help="Path to State Corpus directory (default: corpus)")
    parser.add_argument("--debug-image", "--companion-elf", dest="debug_image", type=str, default=None, help="Optional default nostrip ELF path")
    parser.add_argument("--pid", type=int, default=None, help="Optional default target PID")

    args = parser.parse_args()
    corpus_dir = os.path.abspath(args.corpus)
    os.makedirs(corpus_dir, exist_ok=True)

    runtime = AgentRuntime(corpus_dir=corpus_dir)
    runtime.observation_mode = "LOW_IMPACT"

    static_dir = get_workspace_static_dir()
    server = run_server(runtime=runtime, host=args.host, port=args.port, static_dir=static_dir)

    url = f"http://{args.host}:{args.port}"
    print("========================================")
    print(" dynamicState Trace Workspace UI")
    print(f" {url}")
    print(" Legacy UI still available at: ./bin/dynamic-state-ui")
    print(" Press Ctrl+C to terminate.")
    print("========================================")
    sys.stdout.flush()

    try:
        run_server_loop(server)
    finally:
        print("\nShutting down dynamicState Trace Workspace UI...")


if __name__ == "__main__":
    main()
