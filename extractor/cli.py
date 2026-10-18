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
from typing import Any, Dict, List, Optional, Set, Tuple

from .memory_capture import MemoryCapture
from .offline_analyzer import OfflineMemoryAnalyzer
from .investigation import InvestigationManager


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
    anlz_parser.add_argument("--show-objects", action="store_true", default=False,
                             help="Display all decoded objects")
    anlz_parser.add_argument("--show-provenance", action="store_true", default=False,
                             help="Display detailed provenance for objects and fields")
    anlz_parser.add_argument("--show-diagnostics", action="store_true", default=False,
                             help="Display structured diagnostics")
    anlz_parser.add_argument("--output", type=str, default=None,
                             help="Optional output path to save semantic state JSON")

    # 8. investigate
    inv_parser = subparsers.add_parser("investigate", help="Execute an evidence-first investigation workflow")
    inv_parser.add_argument("--goal", type=str, required=True, help="Natural language investigation goal")
    inv_parser.add_argument("--snapshot", type=str, default=None, help="Snapshot ID or path")
    inv_parser.add_argument("--memory-snapshot", type=str, default=None, help="Path to raw memory snapshot directory")
    inv_parser.add_argument("--debug-image", type=str, default=None, help="Path to external debug image / ELF binary")
    inv_parser.add_argument("--pid", type=int, default=None, help="Target process PID")
    inv_parser.add_argument("--corpus", type=str, default="corpus", help="State Corpus directory (default: corpus)")
    inv_parser.add_argument("--output", type=str, default=None, help="Path to save investigation report JSON")
    inv_parser.add_argument("--json", action="store_true", default=False, help="Print output in JSON format")
    inv_parser.add_argument("--authorize-target", action="store_true", default=False, help="Explicitly authorize live target interaction")

    # 9. compare
    cmp_parser = subparsers.add_parser("compare", help="Compare two observations semantically with uncertainty tracking")
    cmp_parser.add_argument("--snapshot-a", type=str, required=True, help="First snapshot ID or path")
    cmp_parser.add_argument("--snapshot-b", type=str, required=True, help="Second snapshot ID or path")
    cmp_parser.add_argument("--debug-image", type=str, default=None, help="Optional external debug image")
    cmp_parser.add_argument("--corpus", type=str, default="corpus", help="State Corpus directory (default: corpus)")
    cmp_parser.add_argument("--output", type=str, default=None, help="Path to save comparison JSON")
    # 10. trace-function
    trace_parser = subparsers.add_parser("trace-function", help="Trace function entry and return using eBPF uprobes (Phase 1 PoC)")
    trace_parser.add_argument("--pid", type=int, required=True, help="Target process PID")
    trace_parser.add_argument("--binary", type=str, required=True, help="Target binary ELF path")
    trace_parser.add_argument("--function", type=str, required=True, help="Target function symbol name")
    trace_parser.add_argument("--debug-image", type=str, default=None, help="Optional external debug image")
    trace_parser.add_argument("--duration", type=float, default=3.0, help="Tracing duration in seconds (default: 3.0)")
    trace_parser.add_argument("--entry-only", action="store_true", default=False, help="Trace function entry only (skip uretprobe)")
    trace_parser.add_argument("--output", type=str, default=None, help="Optional output path to save JSON trace session")
    trace_parser.add_argument("--json", action="store_true", default=False, help="Print trace results in JSON format")
    trace_parser.add_argument("--no-verify-build-id", action="store_true", default=False, help="Skip build-id verification")

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

        if args.pid:
            try:
                print(f"Pre-capturing running process PID {args.pid}...")
                res = runtime.fast_capture(pid=args.pid, debug_image=args.debug_image)
                if res.success:
                    print(f"Successfully captured PID {args.pid}: snapshot {res.data.get('snapshot_id')}")
                else:
                    print(f"WARNING: Initial capture of PID {args.pid} failed: {res.error.message if res.error else 'Unknown error'}", file=sys.stderr)
            except Exception as exc:
                print(f"WARNING: Could not pre-capture PID {args.pid}: {exc}", file=sys.stderr)

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
                            elif len(parts) >= 3:
                                start = int(parts[1], 16)
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

        # Output format matching Section 21
        print("Semantic State")
        print(f"Status: {status}\n")

        objs_by_id = {o["object_id"]: o for o in sem_state.objects}
        visited_nodes = set()

        if sem_state.roots:
            print("Root:")
            for r in sem_state.roots:
                print(f"  {r.get('name')}: {r.get('type')}")
            print()

        def _print_tree(node_id: str, indent: int, ancestors: Optional[Set[str]] = None):
            if ancestors is None:
                ancestors = set()
            if node_id in ancestors or indent > 12:
                return
            curr_ancestors = set(ancestors)
            curr_ancestors.add(node_id)

            obj = objs_by_id.get(node_id)
            if not obj:
                return
            for f in obj.get("fields", []):
                fname = f.get("name", "")
                fref = f.get("reference") or f.get("object_ref")
                fval = f.get("value")
                fst = f.get("status", "")
                if fref and fref in objs_by_id:
                    child_t = objs_by_id[fref].get("type", "")
                    type_suffix = f": {child_t}" if child_t else ""
                    print(f"{'  ' * indent}{fname}{type_suffix}")
                    if fref in curr_ancestors:
                        continue
                    _print_tree(fref, indent + 1, curr_ancestors)
                else:
                    val_str = f"{fval}" if fval is not None else (fst or "None")
                    print(f"{'  ' * indent}{fname}: {val_str}")

        for r in sem_state.roots:
            rname = r.get("name", "Root")
            ref = r.get("object_ref")
            print(f"{rname}")
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

        if args.show_objects:
            print("\nObjects:")
            for o in sem_state.objects:
                print(f"  - [{o.get('object_id')}]: {o.get('type')} at {o.get('hex_address', hex(o.get('address', 0)))} (status: {o.get('status')})")

        if args.show_object:
            target_obj = sem_state.get_object_by_path(args.show_object)
            if not target_obj:
                target_obj = sem_state.get_object(args.show_object)
            if target_obj:
                print(f"\nObject [{args.show_object}]:")
                print(json.dumps(target_obj, indent=2))
            else:
                print(f"\nObject not found: {args.show_object}", file=sys.stderr)

        if args.show_provenance:
            print("\nProvenance:")
            for o in sem_state.objects:
                oid = o.get("object_id")
                otype = o.get("type")
                opath = o.get("primary_path", oid)
                print(f"  Object [{opath}] ({otype} at {hex(o.get('address', 0))}):")
                for f in o.get("fields", []):
                    fprov = f.get("provenance")
                    if fprov:
                        print(f"    - {f.get('name')}: {json.dumps(fprov)}")

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

    elif args.command == "investigate":
        mgr = InvestigationManager(corpus_dir=args.corpus)
        try:
            report = mgr.start_investigation(
                goal=args.goal,
                snapshot_id=args.snapshot,
                memory_snapshot_path=args.memory_snapshot,
                pid=args.pid,
                debug_image=args.debug_image,
                authorize_target=args.authorize_target,
            )

            if args.output:
                out_p = os.path.abspath(args.output)
                os.makedirs(os.path.dirname(out_p), exist_ok=True)
                with open(out_p, "w", encoding="utf-8") as f:
                    json.dump(report, f, indent=2)
                print(f"Investigation report saved to {out_p}")

            if args.json:
                print(json.dumps(report, indent=2, ensure_ascii=False))
            else:
                print("================================================================================")
                print(f" dynamicState Investigation Report: {report.get('investigation_id')}")
                print("================================================================================")
                print(f"Goal:        {report.get('goal')}")
                print(f"Status:      {report.get('status')}")
                print(f"Persistence: {report.get('persistence', 'EPHEMERAL_PROCESS_LOCAL')}")
                print(f"Date:        {report.get('created_at')}\n")

                # Target Identity
                t_id = report.get("target_ref", {})
                t_details = report.get("stages", {}).get("target_identity", {}).get("details", {})
                print("--- [ Target & Build Identity ] ---")
                print(f"  Executable:     {t_details.get('executable', 'offline_artifact')}")
                print(f"  Target Build ID:{t_details.get('target_build_id') or 'N/A'}")
                print(f"  Debug Build ID: {t_details.get('debug_build_id') or 'N/A'}")
                reason_str = f" ({t_details.get('build_id_reason')})" if t_details.get("build_id_reason") else ""
                print(f"  Build ID Status:{t_details.get('build_id_status', 'UNKNOWN')}{reason_str}\n")

                # Capture Quality
                q_details = report.get("stages", {}).get("capture_quality", {}).get("details", {})
                print("--- [ Capture Quality & Consistency ] ---")
                print(f"  Consistency:    {q_details.get('consistency_level', 'UNKNOWN')}")
                print(f"  Partial Reads:  {q_details.get('partial_reads', 0)}")
                print(f"  Failed Reads:   {q_details.get('failed_reads', 0)}")
                for lim in q_details.get("limitations", []):
                    print(f"  * Note: {lim}")
                print()

                # Static Code Links
                static_details = report.get("stages", {}).get("static_code_link", {}).get("details", {})
                if static_details.get("resolved_links"):
                    print("--- [ Static Code References ] ---")
                    for link in static_details["resolved_links"]:
                        kind = link.get("link_kind", "UNRESOLVED")
                        verified = "[VERIFIED]" if link.get("is_verified") else "[CANDIDATE]"
                        sym = link.get("symbol_name") or link.get("type", "unknown")
                        lim = f" (⚠️ {link['relationship_limitation']})" if link.get("relationship_limitation") else ""
                        loc = f" at {link.get('decl_file', 'source')}:{link.get('decl_line', '?')}" if link.get('decl_file') else ""
                        print(f"  * {verified} {kind}: {sym}{loc}{lim}")
                    print()

                # Findings
                findings = report.get("findings", [])
                facts = [f for f in findings if f.get("category") == "fact"]
                hypotheses = [f for f in findings if f.get("category") == "hypothesis"]
                unknowns = [f for f in findings if f.get("category") == "unknown"]

                print(f"--- [ Findings ({len(findings)}) ] ---")
                if facts:
                    print("  [Observed Facts]")
                    for f in facts:
                        status_str = f" [{f.get('status')}]" if f.get("status") else ""
                        print(f"    *{status_str} {f.get('title')}: {f.get('description')}")
                        if f.get("c_type_path"):
                            print(f"      Path: {f.get('c_type_path')}")
                if hypotheses:
                    print("  [Hypotheses / Potential Invariants]")
                    for f in hypotheses:
                        print(f"    ? {f.get('title')}: {f.get('description')}")
                if unknowns:
                    print("  [Unknowns / Unresolved Data]")
                    for f in unknowns:
                        status_str = f" [{f.get('status')}]" if f.get("status") else ""
                        print(f"    !{status_str} {f.get('title')}: {f.get('description')}")
                print()

                # Recommended Next Steps
                next_steps = report.get("next_steps", [])
                if next_steps:
                    print(f"--- [ Recommended Next Steps ({len(next_steps)}) ] ---")
                    for i, step in enumerate(next_steps, 1):
                        sug = "[SUGGESTION]" if step.get("is_suggestion") else "[EXECUTED]"
                        print(f"  {i}. {sug} {step.get('description')}")
                        print(f"     Rationale: {step.get('rationale')} (Risk: {step.get('risk_level')})")
                print("================================================================================")

            sys.exit(0 if report.get("status") in ("COMPLETED", "PARTIAL") else 1)

        except Exception as exc:
            print(f"ERROR: Investigation failed: {exc}", file=sys.stderr)
            sys.exit(1)

    elif args.command == "compare":
        mgr = InvestigationManager(corpus_dir=args.corpus)
        try:
            session = mgr.start_investigation(
                goal=f"Compare {args.snapshot_a} vs {args.snapshot_b}",
                snapshot_id=args.snapshot_a,
                debug_image=args.debug_image
            )
            cmp_res = mgr.compare_observations(
                session["investigation_id"],
                args.snapshot_a,
                args.snapshot_b
            )

            if args.output:
                out_p = os.path.abspath(args.output)
                os.makedirs(os.path.dirname(out_p), exist_ok=True)
                with open(out_p, "w", encoding="utf-8") as f:
                    json.dump(cmp_res, f, indent=2)
                print(f"Comparison saved to {out_p}")

            if args.json:
                print(json.dumps(cmp_res, indent=2, ensure_ascii=False))
            else:
                print(f"Comparison: {args.snapshot_a} <-> {args.snapshot_b}")
                print(f"Summary: {json.dumps(cmp_res.get('summary', {}), indent=2)}")
                if cmp_res.get("uncertainty"):
                    print(f"Uncertainty: {cmp_res['uncertainty']}")
                changes = cmp_res.get("changes", [])
                print(f"Changes ({len(changes)}):")
                for c in changes[:20]:
                    print(f"  - [{c.get('kind')}] {c.get('path', c.get('object_id'))}: {c.get('before')} -> {c.get('after')}")

            sys.exit(0)
        except Exception as exc:
            print(f"ERROR: Comparison failed: {exc}", file=sys.stderr)
            sys.exit(1)

    elif args.command in ("trace-function", "trace-ebpf"):
        from .ebpf_tracer import EbpfTracer
        tracer = EbpfTracer()
        session = tracer.trace(
            pid=args.pid,
            binary_path=args.binary,
            function_name=args.function,
            debug_image=args.debug_image,
            duration_s=args.duration,
            entry_only=args.entry_only,
            verify_build_id=not args.no_verify_build_id,
        )
        res_dict = session.to_dict()
        if args.output:
            out_p = os.path.abspath(args.output)
            os.makedirs(os.path.dirname(out_p), exist_ok=True)
            with open(out_p, "w", encoding="utf-8") as f:
                json.dump(res_dict, f, indent=2)
            print(f"Trace session saved to {out_p}")

        if args.json:
            print(json.dumps(res_dict, indent=2))
        else:
            print(f"eBPF Trace Session: {session.session_id} (Status: {session.status})")
            print(f"Target PID: {session.target_pid} | Binary: {session.target_binary}")
            print(f"Build ID Status: {session.build_id_status} | Probe Offset: {session.probe_offset}")
            print(f"Function: {session.function_name} | Consistency: {session.consistency_level}")
            print(f"Events Captured: {session.total_events} | Lost: {session.lost_events} | Malformed: {session.malformed_records}")
            if session.overhead_stats:
                print(f"Overhead: {session.overhead_stats}")
            if session.error_message:
                print(f"Note/Error: {session.error_message}", file=sys.stderr if session.status in ("FAILED", "PERMISSION_DENIED", "UNSUPPORTED_ENVIRONMENT") else sys.stdout)
            for ev in session.events[:10]:
                print(f"  [{ev.probe_type}] seq={ev.sequence} tid={ev.tid} time={ev.timestamp_ns}")
                if ev.frame_metadata:
                    sp_str = f"0x{ev.frame_metadata.stack_pointer:x}" if ev.frame_metadata.stack_pointer is not None else "None"
                    pc_str = f"0x{ev.frame_metadata.instruction_pointer:x}" if ev.frame_metadata.instruction_pointer is not None else "None"
                    fp_str = f"0x{ev.frame_metadata.frame_pointer:x}" if ev.frame_metadata.frame_pointer is not None else "None"
                    ra_str = f"0x{ev.frame_metadata.return_address:x}" if ev.frame_metadata.return_address is not None else "None"
                    link_pc_str = f"0x{ev.frame_metadata.link_time_address:x}" if ev.frame_metadata.link_time_address is not None else "None"
                    print(f"    SP={sp_str} PC={pc_str} FP={fp_str} RA={ra_str} LinkPC={link_pc_str}")
                if ev.arguments:
                    args_str = ", ".join(f"{k}={v.value}" for k, v in ev.arguments.items())
                    print(f"    Args: {args_str}")
                if ev.return_value:
                    print(f"    Return: {ev.return_value.value}")
                if ev.local_variables:
                    real_locals = {k: v for k, v in ev.local_variables.items() if k != "local_variables"}
                    if real_locals:
                        locs_str = ", ".join(
                            f"{k}={v.value if v.status == 'OBSERVED' else v.status}"
                            for k, v in real_locals.items()
                        )
                        print(f"    Locals: {locs_str}")
        if session.status in ("FAILED", "PERMISSION_DENIED", "UNSUPPORTED_ENVIRONMENT"):
            sys.exit(1)
        sys.exit(0)



if __name__ == "__main__":
    main()
