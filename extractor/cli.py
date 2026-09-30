"""Command-line interface for dynamicState Phase 5.1 Low-Impact Memory Snapshot and Offline Analysis.

Commands:
- capture-memory: Capture process memory without stopping inferior
- analyze-memory: Perform offline DWARF semantic analysis on captured memory
"""

import argparse
import json
import os
import shutil
import sys
import tempfile

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

    # 5. extract-state
    ext_parser = subparsers.add_parser("extract-state", help="Extract semantic runtime state (LOW_IMPACT or CONSISTENT)")
    ext_parser.add_argument("--mode", type=str, default="LOW_IMPACT", choices=["LOW_IMPACT", "CONSISTENT"],
                            help="Observation mode (default: LOW_IMPACT)")
    ext_parser.add_argument("--pid", type=int, default=None, help="Target process PID")
    ext_parser.add_argument("--debug-image", type=str, default=None,
                            help="Path to external debug image / unstripped ELF binary")
    ext_parser.add_argument("--binary", type=str, default=None,
                            help="Path to executable binary (for CONSISTENT mode)")
    ext_parser.add_argument("--policy", type=str, default="ALL_READABLE",
                            choices=["STACK", "HEAP", "GLOBAL", "EXECUTABLE", "SHARED_LIBRARY", "ALL_READABLE", "SELECTED"],
                            help="Region selection policy (default: ALL_READABLE)")
    ext_parser.add_argument("--max-bytes", type=int, default=32 * 1024 * 1024,
                            help="Maximum total bytes to capture (default: 32MB)")
    ext_parser.add_argument("--timeout-ms", type=int, default=2000,
                            help="Capture timeout in milliseconds (default: 2000ms)")
    ext_parser.add_argument("--output", type=str, default=None,
                            help="Optional output path to save semantic snapshot JSON")

    # 6. server
    srv_parser = subparsers.add_parser("server", help="Launch dynamicState Web UI server (host/workstation only)")
    srv_parser.add_argument("--host", type=str, default="127.0.0.1", help="HTTP host to bind (default: 127.0.0.1)")
    srv_parser.add_argument("--port", type=int, default=8000, help="HTTP port to bind (default: 8000)")
    srv_parser.add_argument("--corpus", type=str, default="corpus", help="Path to State Corpus directory (default: corpus)")
    srv_parser.add_argument("--mode", type=str, default="CONSISTENT", choices=["CONSISTENT", "LOW_IMPACT"], help="Observation mode (default: CONSISTENT)")
    srv_parser.add_argument("--snapshot", type=str, default=None, help="Optional snapshot file to load into corpus")
    srv_parser.add_argument("--binary", type=str, default=None, help="Optional target binary path")
    srv_parser.add_argument("--debug-image", type=str, default=None, help="Optional external debug image path")
    srv_parser.add_argument("--pid", type=int, default=None, help="Optional process PID")

    # 7. analyze
    anlz_parser = subparsers.add_parser("analyze", help="Perform offline DWARF semantic reconstruction on RawRuntimeSnapshot")
    anlz_parser.add_argument("--snapshot", type=str, required=True,
                             help="Path to raw memory snapshot JSON file or directory")
    anlz_parser.add_argument("--debug-image", type=str, required=True,
                             help="Path to external debug image / unstripped ELF binary")
    anlz_parser.add_argument("--allow-symbol-mismatch", action="store_true", default=False,
                             help="Allow analysis even if executable build ID mismatches debug image (default: False)")
    anlz_parser.add_argument("--show-roots", action="store_true", default=False,
                             help="Display discovered DWARF roots")
    anlz_parser.add_argument("--show-object", type=str, default=None,
                             help="Display specific object or hierarchical semantic path")
    anlz_parser.add_argument("--show-diagnostics", action="store_true", default=False,
                             help="Display structured diagnostics")
    anlz_parser.add_argument("--output", type=str, default=None,
                             help="Optional output path to save semantic state JSON")

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
            if raw_snap.status in ("FAILED", "PROCESS_EXITED"):
                sys.exit(1)
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

    elif args.command == "extract-state":
        if args.mode == "LOW_IMPACT":
            if not args.pid:
                print("ERROR: --pid is required for LOW_IMPACT observation mode.", file=sys.stderr)
                sys.exit(1)
            if not args.debug_image:
                print("ERROR: --debug-image is required for LOW_IMPACT offline analysis.", file=sys.stderr)
                sys.exit(1)

            capturer = MemoryCapture()
            if not capturer.is_supported:
                print("ERROR: process_vm_readv is not supported on this platform.", file=sys.stderr)
                sys.exit(1)

            tmp_dir = tempfile.mkdtemp(prefix="dynstate_low_impact_")
            try:
                raw_snap = capturer.capture(
                    pid=args.pid,
                    policy=args.policy,
                    output_dir=tmp_dir,
                    max_bytes=args.max_bytes,
                    timeout_ms=args.timeout_ms
                )
                if raw_snap.status in ("FAILED", "PROCESS_EXITED"):
                    print(f"ERROR: Extraction failed: memory capture returned status '{raw_snap.status}'", file=sys.stderr)
                    sys.exit(1)
                analyzer = OfflineMemoryAnalyzer()
                semantic_snap = analyzer.analyze(
                    memory_snapshot=raw_snap,
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
                print(f"ERROR: Extraction failed: {e}", file=sys.stderr)
                sys.exit(1)
            finally:
                shutil.rmtree(tmp_dir, ignore_errors=True)

        elif args.mode == "CONSISTENT":
            from .runtime_controller import RuntimeController
            target_bin = args.binary or args.debug_image
            if not target_bin:
                print("ERROR: --binary or --debug-image is required for CONSISTENT mode.", file=sys.stderr)
                sys.exit(1)
            try:
                ctrl = RuntimeController(binary=target_bin, pid=args.pid, debug_image=args.debug_image)
                snap = ctrl.observe()
                if args.output:
                    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
                    snap.write_json(args.output)
                    print(f"Semantic snapshot saved to {args.output}")
                else:
                    print(json.dumps(snap.to_dict(), indent=2))
                sys.exit(0)
            except Exception as e:
                print(f"ERROR: Consistent extraction failed: {e}", file=sys.stderr)
                sys.exit(1)

    elif args.command == "server":
        from .agent_runtime import AgentRuntime
        from .web.server import run_server, run_server_loop
        corpus_dir = os.path.abspath(args.corpus)
        os.makedirs(corpus_dir, exist_ok=True)
        runtime = AgentRuntime(corpus_dir=corpus_dir)
        runtime.observation_mode = args.mode

        if args.snapshot:
            if os.path.exists(args.snapshot):
                try:
                    with open(args.snapshot) as f:
                        s_data = json.load(f)
                    runtime.corpus.add(s_data)
                except Exception as exc:
                    print(f"WARNING: Could not preload snapshot {args.snapshot}: {exc}", file=sys.stderr)

        server = run_server(runtime=runtime, host=args.host, port=args.port)
        url = f"http://{args.host}:{args.port}"
        print("========================================")
        print(" dynamicState Web UI")
        print(f" {url}")
        print(f" Mode: {runtime.observation_mode}")
        print(f" Corpus: {corpus_dir}")
        print(" Press Ctrl+C to terminate.")
        print("========================================")
        sys.stdout.flush()

        try:
            run_server_loop(server)
        finally:
            print("\nShutting down dynamicState Web UI...")
            sys.exit(0)

    elif args.command == "analyze":
        from .raw_snapshot import RawRuntimeSnapshot
        from .semantic_state import OfflineSemanticEngine

        snap_path = os.path.abspath(args.snapshot)
        if not os.path.exists(snap_path):
            print(f"ERROR: Snapshot path not found: {snap_path}", file=sys.stderr)
            sys.exit(1)

        try:
            if os.path.isdir(snap_path):
                snap = RawRuntimeSnapshot.load(snap_path)
            else:
                with open(snap_path, "r", encoding="utf-8") as f:
                    snap_data = json.load(f)
                snap = RawRuntimeSnapshot.from_dict(snap_data)
                # Load companion memory directory if adjacent
                parent_dir = os.path.dirname(snap_path)
                mem_dir = os.path.join(parent_dir, "memory")
                if os.path.exists(mem_dir):
                    for fn in os.listdir(mem_dir):
                        if fn.startswith("range_") and fn.endswith(".bin"):
                            parts = fn[:-4].split("_")
                            if len(parts) >= 4:
                                start = int(parts[2], 16)
                                with open(os.path.join(mem_dir, fn), "rb") as bf:
                                    snap.register_buffer(start, bf.read())
        except Exception as e:
            print(f"ERROR: Failed loading snapshot: {e}", file=sys.stderr)
            sys.exit(1)

        engine = OfflineSemanticEngine()
        sem_state = engine.reconstruct(
            raw_snapshot=snap,
            debug_image=args.debug_image,
            allow_symbol_mismatch=args.allow_symbol_mismatch,
        )

        prov = sem_state.provenance or {}
        status = prov.get("status", "COMPLETE")
        diagnostics = prov.get("diagnostics", [])

        # Check for symbol mismatch error
        if status == "SYMBOL_MISMATCH":
            print(f"ERROR: Symbol mismatch between snapshot and debug image.", file=sys.stderr)
            for d in diagnostics:
                if d.get("code") == "SYMBOL_MISMATCH":
                    print(f"  Expected Build ID: {d.get('expected_build_id')}", file=sys.stderr)
                    print(f"  Actual Build ID:   {d.get('actual_build_id')}", file=sys.stderr)
            sys.exit(1)

        # Output format matching Section 30
        print("Semantic State\n")
        objs_by_id = {o["object_id"]: o for o in sem_state.objects}
        visited_nodes = set()

        def _print_tree(node_id: str, indent: int):
            if node_id in visited_nodes:
                return
            visited_nodes.add(node_id)
            obj = objs_by_id.get(node_id)
            if not obj:
                return
            for f in obj.get("fields", []):
                fname = f.get("name", "")
                fref = f.get("reference") or f.get("object_ref")
                fval = f.get("value")
                fst = f.get("status", "")
                if fref and fref in objs_by_id:
                    print(f"{'  ' * indent}{fname}")
                    _print_tree(fref, indent + 1)
                else:
                    val_str = f"{fval}" if fval is not None else (fst or "None")
                    print(f"{'  ' * indent}{fname}: {val_str}")

        for r in sem_state.roots:
            rname = r.get("name", "Root")
            print(f"{rname}")
            ref = r.get("object_ref")
            if ref and ref in objs_by_id:
                _print_tree(ref, 1)

        print(f"\nStatus: {status}")
        print(f"Objects: {len(sem_state.objects)}")
        print(f"Roots: {len(sem_state.roots)}")
        print(f"Diagnostics: {len(diagnostics)}")

        if args.show_roots:
            print("\nRoots:")
            for r in sem_state.roots:
                print(f"  - {r.get('name')}: {r.get('type')} at 0x{r.get('address', 0):x} ({r.get('kind')})")

        if args.show_object:
            target_obj = sem_state.get_object_by_path(args.show_object)
            if not target_obj:
                target_obj = sem_state.get_object(args.show_object)
            if target_obj:
                print(f"\nObject [{args.show_object}]:")
                print(json.dumps(target_obj, indent=2))
            else:
                print(f"\nObject not found: {args.show_object}", file=sys.stderr)

        if args.show_diagnostics and diagnostics:
            print("\nDiagnostics:")
            for d in diagnostics:
                print(f"  - [{d.get('code')}] {d.get('message', '')} {d.get('object', '')}")

        if args.output:
            out_p = os.path.abspath(args.output)
            os.makedirs(os.path.dirname(out_p), exist_ok=True)
            with open(out_p, "w", encoding="utf-8") as f:
                json.dump(sem_state.to_dict(), f, indent=2)
            print(f"\nSaved semantic state to {out_p}")

        sys.exit(0 if status in ("COMPLETE", "PARTIAL") else 1)


if __name__ == "__main__":
    main()
