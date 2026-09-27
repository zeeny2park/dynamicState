"""Command-line interface for dynamicState Phase 5.1 Low-Impact Memory Snapshot and Offline Analysis.

Commands:
- capture-memory: Capture process memory without stopping inferior
- analyze-memory: Perform offline DWARF semantic analysis on captured memory
"""

import argparse
import json
import os
import sys

from .memory_capture import MemoryCapture
from .offline_analyzer import OfflineMemoryAnalyzer


def main():
    parser = argparse.ArgumentParser(
        prog="dynamic-state",
        description="dynamicState: Runtime State Exploration & Low-Impact Memory Capture CLI"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # 1. capture-memory
    cap_parser = subparsers.add_parser("capture-memory", help="Capture process memory without stopping execution")
    cap_parser.add_argument("--pid", type=int, required=True, help="Target process PID")
    cap_parser.add_argument("--policy", type=str, default="ALL_READABLE",
                            choices=["STACK", "HEAP", "GLOBAL", "EXECUTABLE", "SHARED_LIBRARY", "ALL_READABLE", "SELECTED"],
                            help="Region selection policy (default: ALL_READABLE)")
    cap_parser.add_argument("--max-bytes", type=int, default=32 * 1024 * 1024,
                            help="Maximum total bytes to capture (default: 32MB)")
    cap_parser.add_argument("--timeout-ms", type=int, default=2000,
                            help="Capture timeout in milliseconds (default: 2000ms)")
    cap_parser.add_argument("--output", type=str, required=True,
                            help="Directory path to save raw memory snapshot")
    cap_parser.add_argument("--snapshot-id", type=str, default=None,
                            help="Optional snapshot identifier")

    # 2. analyze-memory
    ana_parser = subparsers.add_parser("analyze-memory", help="Perform offline semantic analysis on captured memory")
    ana_parser.add_argument("--snapshot", type=str, required=True,
                            help="Path to raw memory snapshot directory")
    ana_parser.add_argument("--debug-image", type=str, required=True,
                            help="Path to external debug image / unstripped ELF binary")
    ana_parser.add_argument("--output", type=str, default=None,
                            help="Output JSON path to save semantic snapshot")

    args = parser.parse_args()

    if args.command == "capture-memory":
        capturer = MemoryCapture()
        if not capturer.is_supported:
            print("ERROR: process_vm_readv is not supported on this platform.", file=sys.stderr)
            sys.exit(1)

        try:
            raw_snap = capturer.capture(
                pid=args.pid,
                policy=args.policy,
                output_dir=args.output,
                max_bytes=args.max_bytes,
                timeout_ms=args.timeout_ms,
                snapshot_id=args.snapshot_id
            )
            print(json.dumps(raw_snap.to_metadata(), indent=2))
            sys.exit(0)
        except Exception as e:
            print(f"ERROR: Memory capture failed: {e}", file=sys.stderr)
            sys.exit(1)

    elif args.command == "analyze-memory":
        analyzer = OfflineMemoryAnalyzer()
        try:
            semantic_snap = analyzer.analyze(
                memory_snapshot=args.snapshot,
                debug_image=args.debug_image
            )
            if args.output:
                os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
                semantic_snap.write_json(args.output)
                print(f"Semantic snapshot saved to {args.output}")
            else:
                print(json.dumps(semantic_snap.to_dict(), indent=2))
            sys.exit(0)
        except Exception as e:
            print(f"ERROR: Offline analysis failed: {e}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
