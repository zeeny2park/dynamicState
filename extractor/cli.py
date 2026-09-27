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
    cap_parser.add_argument("--output", "--output-dir", dest="output", type=str, required=True,
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
                            help="Optional output path to save semantic snapshot JSON")
    # 3. list-modules
    mod_parser = subparsers.add_parser("list-modules", help="Discover and list runtime modules for a process or snapshot")
    mod_parser.add_argument("--pid", type=int, default=None, help="Target process PID")
    mod_parser.add_argument("--snapshot", type=str, default=None, help="Path to raw memory snapshot directory")

    # 4. runtime-info
    subparsers.add_parser("runtime-info", help="Display platform observation capabilities and backend support")

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

    elif args.command == "list-modules":
        from .memory_maps import MemoryMapProvider
        from .memory_snapshot import RawMemorySnapshot
        from .modules import discover_modules

        try:
            if args.snapshot:
                snap = RawMemorySnapshot.load(args.snapshot)
                print(json.dumps(snap.modules, indent=2))
            elif args.pid:
                provider = MemoryMapProvider(args.pid)
                regs = provider.get_regions()
                mods = discover_modules(args.pid, regs)
                print(json.dumps([m.to_dict() for m in mods], indent=2))
            else:
                print("ERROR: Either --pid or --snapshot must be specified.", file=sys.stderr)
                sys.exit(1)
            sys.exit(0)
        except Exception as e:
            print(f"ERROR: Failed listing modules: {e}", file=sys.stderr)
            sys.exit(1)

    elif args.command == "runtime-info":
        capturer = MemoryCapture()
        info = {
            "platform": sys.platform,
            "architecture": os.uname().machine if hasattr(os, "uname") else "unknown",
            "observation_modes": ["CONSISTENT", "LOW_IMPACT"],
            "process_vm_readv_supported": capturer.is_supported,
            "low_impact_safety": {
                "process_stop": False,
                "ptrace": False,
                "sigstop": False,
                "sigcont": False,
                "mutation": False,
            }
        }
        print(json.dumps(info, indent=2))
        sys.exit(0)


if __name__ == "__main__":
    main()
