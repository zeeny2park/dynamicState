"""CLI launcher for dynamicState Web UI MVP.

Usage:
    python3 -m extractor.web [--host 127.0.0.1] [--port 8000] [--corpus corpus]
"""

import argparse
import os
import signal
import sys

from extractor.agent_runtime import AgentRuntime
from extractor.web.server import run_server, run_server_loop


def main():
    parser = argparse.ArgumentParser(
        prog="dynamic-state-ui",
        description="dynamicState: Runtime State Explorer Web UI"
    )
    parser.add_argument("--host", type=str, default="127.0.0.1",
                        help="HTTP host to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000,
                        help="HTTP port to bind (default: 8000)")
    parser.add_argument("--corpus", type=str, default="corpus",
                        help="Path to State Corpus directory (default: corpus)")
    parser.add_argument("--mode", type=str, default="CONSISTENT",
                        choices=["CONSISTENT", "LOW_IMPACT"],
                        help="Initial observation mode (default: CONSISTENT)")
    parser.add_argument("--binary", type=str, default=None,
                        help="Path to target binary (optional)")
    parser.add_argument("--debug-image", type=str, default=None,
                        help="Path to external debug image (optional)")
    parser.add_argument("--pid", type=int, default=None,
                        help="Target process PID (optional)")

    args = parser.parse_args()

    # Initialize AgentRuntime with corpus
    corpus_dir = os.path.abspath(args.corpus)
    os.makedirs(corpus_dir, exist_ok=True)
    runtime = AgentRuntime(corpus_dir=corpus_dir)
    runtime.observation_mode = args.mode

    server = run_server(runtime=runtime, host=args.host, port=args.port)

    url = f"http://{args.host}:{args.port}"
    print("========================================")
    print(" dynamicState Web UI")
    print(f" {url}")
    print(" Mode: " + runtime.observation_mode)
    print(" Corpus: " + corpus_dir)
    print(" Press Ctrl+C to terminate.")
    print("========================================")
    sys.stdout.flush()

    try:
        run_server_loop(server)
    finally:
        print("\nShutting down dynamicState Web UI...")


if __name__ == "__main__":
    main()
