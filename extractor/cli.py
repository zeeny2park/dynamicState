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
from .verdict_engine import sanitize_report_output_path


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
    inv_parser.add_argument("-p", "--pid", type=int, default=None, help="Target process PID")
    inv_parser.add_argument("--corpus", type=str, default="corpus", help="State Corpus directory (default: corpus)")
    inv_parser.add_argument("--output", type=str, default=None, help="Path to save investigation report JSON")
    inv_parser.add_argument("--report-html", dest="report_html_path", type=str, default=None, help="Optional path to write standalone Zero-CDN HTML investigation report")
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

    # 11. connect (Phase 4 simplified workflow)
    conn_p = subparsers.add_parser("connect", help="Validate local/remote target process by PID or name and list recommended state symbols")
    conn_p.add_argument("--pid", type=int, default=None, help="Target process PID")
    conn_p.add_argument("--process-name", type=str, default=None, help="Target process name (auto-discovers PID)")
    conn_p.add_argument("--debug-image", "--companion-elf", dest="debug_image", type=str, required=True, help="Path to non-stripped companion ELF with DWARF")
    conn_p.add_argument("--remote-host", type=str, default=None, help="Optional SSH remote embedded host/IP")
    conn_p.add_argument("--ssh-user", type=str, default=None, help="Optional SSH username")
    conn_p.add_argument("--ssh-port", type=int, default=22, help="SSH port (default: 22)")
    conn_p.add_argument("--ssh-key", type=str, default=None, help="Optional SSH private key path")
    conn_p.add_argument("--ssh-proxy-jump", type=str, default=None, help="Optional SSH ProxyJump")
    conn_p.add_argument("--auto-deploy-collector", action="store_true", default=False, help="Auto-deploy C99 collector to remote target")
    conn_p.add_argument("--corpus", type=str, default="corpus", help="Corpus directory")

    # 12. eval (Phase 4 deep symbol path evaluation)
    eval_p = subparsers.add_parser("eval", help="Evaluate C/C++ symbol path expressions (e.g. g_session.worker.state, g_ptr->field) with 0ms stop")
    eval_p.add_argument("--pid", type=int, required=True, help="Target process PID")
    eval_p.add_argument("--debug-image", "--companion-elf", dest="debug_image", type=str, required=True, help="Path to non-stripped companion ELF")
    eval_p.add_argument("--expr", "--expressions", dest="expr", type=str, required=True, help="Comma-separated C/C++ symbol expressions")
    eval_p.add_argument("--remote-host", type=str, default=None, help="Optional SSH remote host")
    eval_p.add_argument("--ssh-user", type=str, default=None, help="Optional SSH user")
    eval_p.add_argument("--ssh-port", type=int, default=22, help="SSH port")
    eval_p.add_argument("--ssh-key", type=str, default=None, help="Optional SSH key")
    eval_p.add_argument("--ssh-proxy-jump", type=str, default=None, help="Optional SSH ProxyJump")
    eval_p.add_argument("--corpus", type=str, default="corpus", help="Corpus directory")

    # 13. diff (Phase 4 two-point zero-stop diff)
    diff_p = subparsers.add_parser("diff", help="Sample C/C++ symbol expressions twice across wait-ms and report changed vs unchanged fields")
    diff_p.add_argument("--pid", type=int, required=True, help="Target process PID")
    diff_p.add_argument("--debug-image", "--companion-elf", dest="debug_image", type=str, required=True, help="Path to non-stripped companion ELF")
    diff_p.add_argument("--expr", "--expressions", dest="expr", type=str, default=None, help="Optional comma-separated expressions (defaults to top state globals)")
    diff_p.add_argument("--wait-ms", type=int, default=500, help="Interval in ms between captures (default: 500)")
    diff_p.add_argument("--remote-host", type=str, default=None, help="Optional SSH remote host")
    diff_p.add_argument("--ssh-user", type=str, default=None, help="Optional SSH user")
    diff_p.add_argument("--ssh-port", type=int, default=22, help="SSH port")
    diff_p.add_argument("--ssh-key", type=str, default=None, help="Optional SSH key")
    diff_p.add_argument("--ssh-proxy-jump", type=str, default=None, help="Optional SSH ProxyJump")
    diff_p.add_argument("--corpus", type=str, default="corpus", help="Corpus directory")

    # 13b. pool-map (Phase 8 memory pool & buffer array scanner)
    pool_p = subparsers.add_parser("pool-map", help="Scan a memory pool or buffer array (e.g. *gpMem) and render an allocation map chart")
    pool_p.add_argument("-p", "--pid", type=int, required=True, help="Target PID")
    pool_p.add_argument("-d", "--debug-image", "--companion-elf", dest="debug_image", type=str, required=True, help="Local path to nostrip ELF")
    pool_p.add_argument("-e", "--expr", type=str, required=True, help="Pool or array expression (e.g. *gpMem, gpMem->buffers)")
    pool_p.add_argument("-n", "--count", type=int, default=None, help="Optional slot count override")
    pool_p.add_argument("--status-field", type=str, default=None, help="Optional field name indicating slot allocation")
    pool_p.add_argument("--remote-host", type=str, default=None, help="Optional SSH remote host")
    pool_p.add_argument("--ssh-user", type=str, default=None)
    pool_p.add_argument("--ssh-port", type=int, default=22)
    pool_p.add_argument("--ssh-key", type=str, default=None)
    pool_p.add_argument("--ssh-proxy-jump", type=str, default=None)
    pool_p.add_argument("--corpus", type=str, default="corpus")

    # 13c. find-owner (Phase 8 reverse pointer & thread ownership lookup)
    own_p = subparsers.add_parser("find-owner", help="Find which thread or worker context is using a specific buffer slot (e.g. gpMem->buffers[9])")
    own_p.add_argument("-p", "--pid", type=int, required=True, help="Target PID")
    own_p.add_argument("-d", "--debug-image", "--companion-elf", dest="debug_image", type=str, required=True, help="Local path to nostrip ELF")
    own_p.add_argument("-e", "--expr", type=str, required=True, help="Target slot/symbol expression (e.g. gpMem->buffers[9] or gpMem[9])")
    own_p.add_argument("--remote-host", type=str, default=None, help="Optional SSH remote host")
    own_p.add_argument("--ssh-user", type=str, default=None)
    own_p.add_argument("--ssh-port", type=int, default=22)
    own_p.add_argument("--ssh-key", type=str, default=None)
    own_p.add_argument("--ssh-proxy-jump", type=str, default=None)
    own_p.add_argument("--corpus", type=str, default="corpus")

    # 13d. workspace (Phase 9 Minimalist Chat + Trace Workspace Web UI)
    ws_p = subparsers.add_parser("workspace", help="Launch the minimalist Gemini-style Chat + Process Trace Workspace Web UI")
    ws_p.add_argument("--host", type=str, default="127.0.0.1", help="HTTP host to bind (default: 127.0.0.1)")
    ws_p.add_argument("--port", type=int, default=8080, help="HTTP port to bind (default: 8080)")
    ws_p.add_argument("--corpus", type=str, default="corpus", help="Corpus directory")

    # 14. recipe (Phase 4 guided diagnostic recipes & Golden Baselines)
    rec_p = subparsers.add_parser("recipe", help="Run a guided diagnostic recipe (instant_xray, before_after_diff, timeseries_watch) or Golden Baseline check")
    rec_p.add_argument("--name", type=str, default="instant_xray", choices=["instant_xray", "before_after_diff", "timeseries_watch", "save_baseline", "compare_baseline"], help="Recipe name")
    rec_p.add_argument("--pid", type=int, required=True, help="Target process PID")
    rec_p.add_argument("--debug-image", "--companion-elf", dest="debug_image", type=str, required=True, help="Path to non-stripped companion ELF")
    rec_p.add_argument("--expr", type=str, default=None, help="Optional comma-separated expressions")
    rec_p.add_argument("--duration-ms", type=int, default=1000, help="Observation window in ms (default: 1000)")
    rec_p.add_argument("--interval-ms", type=int, default=200, help="Sampling interval in ms (default: 200)")
    rec_p.add_argument("--baseline-id", type=str, default=None, help="Golden baseline ID for compare_baseline")
    rec_p.add_argument("--label", type=str, default="Golden Baseline", help="Label for save_baseline")
    rec_p.add_argument("--remote-host", type=str, default=None, help="Optional SSH remote host")
    rec_p.add_argument("--ssh-user", type=str, default=None, help="Optional SSH user")
    rec_p.add_argument("--ssh-port", type=int, default=22, help="SSH port")
    rec_p.add_argument("--ssh-key", type=str, default=None, help="Optional SSH key")
    rec_p.add_argument("--ssh-proxy-jump", type=str, default=None, help="Optional SSH ProxyJump")
    rec_p.add_argument("--corpus", type=str, default="corpus", help="Corpus directory")

    # 15. Phase 10 CLI subcommands (watch-until, traverse-list, callstacks, audit, resolve-func, inspect-shm)
    wu_p = subparsers.add_parser("watch-until", help="Poll target until condition expression triggers (0.00ms stop)")
    wu_p.add_argument("-p", "--pid", type=int, required=True)
    wu_p.add_argument("-d", "--debug-image", "--companion-elf", dest="debug_image", type=str, required=True)
    wu_p.add_argument("-c", "--condition", type=str, required=True, help="Condition expression e.g. gpMem->active_buffers >= 5")
    wu_p.add_argument("--poll-ms", type=int, default=40)
    wu_p.add_argument("--timeout-ms", type=int, default=2000)
    wu_p.add_argument("--hold-ms", type=int, default=0)
    wu_p.add_argument("--remote-host", type=str, default=None)
    wu_p.add_argument("--ssh-user", type=str, default=None)
    wu_p.add_argument("--ssh-port", type=int, default=22)
    wu_p.add_argument("--ssh-key", type=str, default=None)
    wu_p.add_argument("--ssh-proxy-jump", type=str, default=None)
    wu_p.add_argument("--corpus", type=str, default="corpus")

    tl_p = subparsers.add_parser("traverse-list", help="Traverse a non-contiguous linked list or pointer chain (0.00ms stop)")
    tl_p.add_argument("-p", "--pid", type=int, required=True)
    tl_p.add_argument("-d", "--debug-image", "--companion-elf", dest="debug_image", type=str, required=True)
    tl_p.add_argument("-e", "--expr", type=str, required=True, help="Head pointer/struct expression e.g. g_task_list")
    tl_p.add_argument("--next-field", type=str, default="next")
    tl_p.add_argument("--max-depth", type=int, default=64)
    tl_p.add_argument("--remote-host", type=str, default=None)
    tl_p.add_argument("--ssh-user", type=str, default=None)
    tl_p.add_argument("--ssh-port", type=int, default=22)
    tl_p.add_argument("--ssh-key", type=str, default=None)
    tl_p.add_argument("--ssh-proxy-jump", type=str, default=None)
    tl_p.add_argument("--corpus", type=str, default="corpus")

    cs_p = subparsers.add_parser("callstacks", help="Unwind thread callstacks and inspect mutex locks / deadlocks (0.00ms stop)")
    cs_p.add_argument("-p", "--pid", type=int, required=True)
    cs_p.add_argument("-d", "--debug-image", "--companion-elf", dest="debug_image", type=str, required=True)
    cs_p.add_argument("--tid", type=int, default=None)
    cs_p.add_argument("--remote-host", type=str, default=None)
    cs_p.add_argument("--ssh-user", type=str, default=None)
    cs_p.add_argument("--ssh-port", type=int, default=22)
    cs_p.add_argument("--ssh-key", type=str, default=None)
    cs_p.add_argument("--ssh-proxy-jump", type=str, default=None)
    cs_p.add_argument("--corpus", type=str, default="corpus")

    au_p = subparsers.add_parser("audit", help="Audit DWARF pointers, bools, enums, and memory pools for corruption (0.00ms stop)")
    au_p.add_argument("-p", "--pid", type=int, required=True)
    au_p.add_argument("-d", "--debug-image", "--companion-elf", dest="debug_image", type=str, required=True)
    au_p.add_argument("-e", "--expr", type=str, default=None)
    au_p.add_argument("--remote-host", type=str, default=None)
    au_p.add_argument("--ssh-user", type=str, default=None)
    au_p.add_argument("--ssh-port", type=int, default=22)
    au_p.add_argument("--ssh-key", type=str, default=None)
    au_p.add_argument("--ssh-proxy-jump", type=str, default=None)
    au_p.add_argument("--corpus", type=str, default="corpus")

    rf_p = subparsers.add_parser("resolve-func", help="Resolve function pointers and C++ vtable slots to source file:line (0.00ms stop)")
    rf_p.add_argument("-p", "--pid", type=int, required=True)
    rf_p.add_argument("-d", "--debug-image", "--companion-elf", dest="debug_image", type=str, required=True)
    rf_p.add_argument("-e", "--expr", type=str, required=True)
    rf_p.add_argument("--remote-host", type=str, default=None)
    rf_p.add_argument("--ssh-user", type=str, default=None)
    rf_p.add_argument("--ssh-port", type=int, default=22)
    rf_p.add_argument("--ssh-key", type=str, default=None)
    rf_p.add_argument("--ssh-proxy-jump", type=str, default=None)
    rf_p.add_argument("--corpus", type=str, default="corpus")

    shm_p = subparsers.add_parser("inspect-shm", help="Inspect shared memory / IPC mappings with DWARF type overlay casting (0.00ms stop)")
    shm_p.add_argument("-p", "--pid", type=int, required=True)
    shm_p.add_argument("-d", "--debug-image", "--companion-elf", dest="debug_image", type=str, required=True)
    shm_p.add_argument("--cast-type", type=str, default=None)
    shm_p.add_argument("--address", type=str, default=None)
    shm_p.add_argument("--shm-name", type=str, default=None)
    shm_p.add_argument("--remote-host", type=str, default=None)
    shm_p.add_argument("--ssh-user", type=str, default=None)
    shm_p.add_argument("--ssh-port", type=int, default=22)
    shm_p.add_argument("--ssh-key", type=str, default=None)
    shm_p.add_argument("--ssh-proxy-jump", type=str, default=None)
    shm_p.add_argument("--corpus", type=str, default="corpus")

    fl_p = subparsers.add_parser("frame-locals", help="Decode active thread stack frame parameters and local variables (0.00ms stop)")
    fl_p.add_argument("-p", "--pid", type=int, required=True)
    fl_p.add_argument("-d", "--debug-image", "--companion-elf", dest="debug_image", type=str, required=True)
    fl_p.add_argument("--tid", type=int, default=None)
    fl_p.add_argument("--remote-host", type=str, default=None)
    fl_p.add_argument("--ssh-user", type=str, default=None)
    fl_p.add_argument("--ssh-port", type=int, default=22)
    fl_p.add_argument("--ssh-key", type=str, default=None)
    fl_p.add_argument("--ssh-proxy-jump", type=str, default=None)
    fl_p.add_argument("--corpus", type=str, default="corpus")

    at_p = subparsers.add_parser("auto-triage", help="Run 1-call composite zero-stop incident auto-triage across memory, locks, pools, and lists")
    at_p.add_argument("-p", "--pid", type=int, required=True)
    at_p.add_argument("-d", "--debug-image", "--companion-elf", dest="debug_image", type=str, required=True)
    at_p.add_argument("--remote-host", type=str, default=None)
    at_p.add_argument("--ssh-user", type=str, default=None)
    at_p.add_argument("--ssh-port", type=int, default=22)
    at_p.add_argument("--ssh-key", type=str, default=None)
    at_p.add_argument("--ssh-proxy-jump", type=str, default=None)
    at_p.add_argument("--corpus", type=str, default="corpus")

    ipc_p = subparsers.add_parser("ipc-pipeline", help="Analyze cross-process shared memory & IPC pipeline bottlenecks (0.00ms stop)")
    ipc_p.add_argument("-p", "--pid", type=int, required=True)
    ipc_p.add_argument("-d", "--debug-image", "--companion-elf", dest="debug_image", type=str, required=True)
    ipc_p.add_argument("--cast-type", type=str, default=None)
    ipc_p.add_argument("--address", type=str, default=None)
    ipc_p.add_argument("--shm-name", type=str, default=None)
    ipc_p.add_argument("--remote-host", type=str, default=None)
    ipc_p.add_argument("--ssh-user", type=str, default=None)
    ipc_p.add_argument("--ssh-port", type=int, default=22)
    ipc_p.add_argument("--ssh-key", type=str, default=None)
    ipc_p.add_argument("--ssh-proxy-jump", type=str, default=None)
    ipc_p.add_argument("--corpus", type=str, default="corpus")

    hp_p = subparsers.add_parser("scan-heap", help="Scan [heap] for C++ polymorphic objects via vtable and detect unreachable leaks (0.00ms stop)")
    hp_p.add_argument("-p", "--pid", type=int, required=True)
    hp_p.add_argument("-d", "--debug-image", "--companion-elf", dest="debug_image", type=str, required=True)
    hp_p.add_argument("--class-filter", type=str, default=None)
    hp_p.add_argument("--remote-host", type=str, default=None)
    hp_p.add_argument("--ssh-user", type=str, default=None)
    hp_p.add_argument("--ssh-port", type=int, default=22)
    hp_p.add_argument("--ssh-key", type=str, default=None)
    hp_p.add_argument("--ssh-proxy-jump", type=str, default=None)
    hp_p.add_argument("--corpus", type=str, default="corpus")

    dg_p = subparsers.add_parser("dependency-graph", help="Synthesize cross-entity dependency & causal graph (0.00ms stop)")
    dg_p.add_argument("-p", "--pid", type=int, required=True)
    dg_p.add_argument("-d", "--debug-image", "--companion-elf", dest="debug_image", type=str, required=True)
    dg_p.add_argument("--remote-host", type=str, default=None)
    dg_p.add_argument("--ssh-user", type=str, default=None)
    dg_p.add_argument("--ssh-port", type=int, default=22)
    dg_p.add_argument("--ssh-key", type=str, default=None)
    dg_p.add_argument("--ssh-proxy-jump", type=str, default=None)
    dg_p.add_argument("--corpus", type=str, default="corpus")

    cs_p = subparsers.add_parser("correlate-source", help="Correlate DWARF source locations with C/C++ code and inline live variables (0.00ms stop)")
    cs_p.add_argument("-p", "--pid", type=int, required=True)
    cs_p.add_argument("-d", "--debug-image", "--companion-elf", dest="debug_image", type=str, required=True)
    cs_p.add_argument("--source-location", type=str, default=None)
    cs_p.add_argument("--tid", type=int, default=None)
    cs_p.add_argument("--context-lines", type=int, default=8)
    cs_p.add_argument("--remote-host", type=str, default=None)
    cs_p.add_argument("--ssh-user", type=str, default=None)
    cs_p.add_argument("--ssh-port", type=int, default=22)
    cs_p.add_argument("--ssh-key", type=str, default=None)
    cs_p.add_argument("--ssh-proxy-jump", type=str, default=None)
    cs_p.add_argument("--corpus", type=str, default="corpus")

    is_p = subparsers.add_parser("investigate-symptom", help="Autonomous symptom-driven root-cause investigator (0.00ms stop)")
    is_p.add_argument("-p", "--pid", type=int, required=True)
    is_p.add_argument("-d", "--debug-image", "--companion-elf", dest="debug_image", type=str, required=True)
    is_p.add_argument("-q", "--query", "--symptom", dest="symptom_query", type=str, default="왜 멈췄지? 전체적인 문제를 종합 분석해줘")
    is_p.add_argument("--remote-host", type=str, default=None)
    is_p.add_argument("--ssh-user", type=str, default=None)
    is_p.add_argument("--ssh-port", type=int, default=22)
    is_p.add_argument("--ssh-key", type=str, default=None)
    is_p.add_argument("--ssh-proxy-jump", type=str, default=None)
    is_p.add_argument("--corpus", type=str, default="corpus")

    sh_p = subparsers.add_parser("hotspots", help="Zero-stop statistical CPU & callstack hotspot profiler (0.00ms stop)")
    sh_p.add_argument("-p", "--pid", type=int, required=True)
    sh_p.add_argument("-d", "--debug-image", "--companion-elf", dest="debug_image", type=str, required=True)
    sh_p.add_argument("--samples", dest="samples_count", type=int, default=6)
    sh_p.add_argument("--interval-ms", type=int, default=35)
    sh_p.add_argument("--remote-host", type=str, default=None)
    sh_p.add_argument("--ssh-user", type=str, default=None)
    sh_p.add_argument("--ssh-port", type=int, default=22)
    sh_p.add_argument("--ssh-key", type=str, default=None)
    sh_p.add_argument("--ssh-proxy-jump", type=str, default=None)
    sh_p.add_argument("--corpus", type=str, default="corpus")

    fz_p = subparsers.add_parser("fuzzy-resolve", help="Resolve vague natural-language concepts to DWARF symbols and live values (0.00ms stop)")
    fz_p.add_argument("-p", "--pid", type=int, required=True)
    fz_p.add_argument("-d", "--debug-image", "--companion-elf", dest="debug_image", type=str, required=True)
    fz_p.add_argument("-q", "--query", dest="natural_query", type=str, required=True)
    fz_p.add_argument("--limit", type=int, default=5)
    fz_p.add_argument("--remote-host", type=str, default=None)
    fz_p.add_argument("--ssh-user", type=str, default=None)
    fz_p.add_argument("--ssh-port", type=int, default=22)
    fz_p.add_argument("--ssh-key", type=str, default=None)
    fz_p.add_argument("--ssh-proxy-jump", type=str, default=None)
    fz_p.add_argument("--corpus", type=str, default="corpus")

    fr_p = subparsers.add_parser("flight-recorder", help="Zero-stop Anomaly Time-Machine Flight Recorder ring buffer (0.00ms stop)")
    fr_p.add_argument("-p", "--pid", type=int, required=True)
    fr_p.add_argument("-d", "--debug-image", "--companion-elf", dest="debug_image", type=str, required=True)
    fr_p.add_argument("--frames", dest="frames_count", type=int, default=8)
    fr_p.add_argument("--interval-ms", type=int, default=25)
    fr_p.add_argument("--remote-host", type=str, default=None)
    fr_p.add_argument("--ssh-user", type=str, default=None)
    fr_p.add_argument("--ssh-port", type=int, default=22)
    fr_p.add_argument("--ssh-key", type=str, default=None)
    fr_p.add_argument("--ssh-proxy-jump", type=str, default=None)
    fr_p.add_argument("--corpus", type=str, default="corpus")

    bd_p = subparsers.add_parser("behavioral-drift", help="Zero-stop multi-dimensional behavioral drift detector (0.00ms stop)")
    bd_p.add_argument("-p", "--pid", type=int, required=True)
    bd_p.add_argument("-d", "--debug-image", "--companion-elf", dest="debug_image", type=str, required=True)
    bd_p.add_argument("--save-baseline", action="store_true")
    bd_p.add_argument("--remote-host", type=str, default=None)
    bd_p.add_argument("--ssh-user", type=str, default=None)
    bd_p.add_argument("--ssh-port", type=int, default=22)
    bd_p.add_argument("--ssh-key", type=str, default=None)
    bd_p.add_argument("--ssh-proxy-jump", type=str, default=None)
    bd_p.add_argument("--corpus", type=str, default="corpus")

    tls_p = subparsers.add_parser("tls-vars", help="Decode per-thread TLS (__thread / thread_local) variables in 0.00ms zero-stop mode")
    tls_p.add_argument("-p", "--pid", type=int, required=True)
    tls_p.add_argument("-d", "--debug-image", "--companion-elf", dest="debug_image", type=str, required=True)
    tls_p.add_argument("--tid", type=int, default=None)
    tls_p.add_argument("-v", "--vars", dest="variable_names", type=str, default=None, help="Comma-separated TLS variable names")
    tls_p.add_argument("--remote-host", type=str, default=None)
    tls_p.add_argument("--ssh-user", type=str, default=None)
    tls_p.add_argument("--ssh-port", type=int, default=22)
    tls_p.add_argument("--ssh-key", type=str, default=None)
    tls_p.add_argument("--ssh-proxy-jump", type=str, default=None)
    tls_p.add_argument("--corpus", type=str, default="corpus")

    vc_p = subparsers.add_parser("verify-consistency", help="Optimistic Seqlock double-read concurrency verifier (0.00ms stop)")
    vc_p.add_argument("-p", "--pid", type=int, required=True)
    vc_p.add_argument("-d", "--debug-image", "--companion-elf", dest="debug_image", type=str, required=True)
    vc_p.add_argument("-e", "--expressions", type=str, default=None, help="Comma-separated expressions to verify")
    vc_p.add_argument("--retries", type=int, default=3)
    vc_p.add_argument("--delay-ms", dest="inter_read_delay_ms", type=int, default=4)
    vc_p.add_argument("--remote-host", type=str, default=None)
    vc_p.add_argument("--ssh-user", type=str, default=None)
    vc_p.add_argument("--ssh-port", type=int, default=22)
    vc_p.add_argument("--ssh-key", type=str, default=None)
    vc_p.add_argument("--ssh-proxy-jump", type=str, default=None)
    vc_p.add_argument("--corpus", type=str, default="corpus")

    dpdk_p = subparsers.add_parser("dpdk-lcores", help="Inspect DPDK isolated-core dedicated lcores, PMD poll loops, lockless rings, and spinlocks (0.00ms stop)")
    dpdk_p.add_argument("-p", "--pid", type=int, required=True)
    dpdk_p.add_argument("-d", "--debug-image", "--companion-elf", dest="debug_image", type=str, required=True)
    dpdk_p.add_argument("--window-ms", dest="sample_window_ms", type=int, default=40)
    dpdk_p.add_argument("--rings", dest="ring_expressions", type=str, default=None, help="Comma-separated ring expressions")
    dpdk_p.add_argument("--spinlocks", dest="spinlock_expressions", type=str, default=None, help="Comma-separated spinlock expressions")
    dpdk_p.add_argument("--remote-host", type=str, default=None)
    dpdk_p.add_argument("--ssh-user", type=str, default=None)
    dpdk_p.add_argument("--ssh-port", type=int, default=22)
    dpdk_p.add_argument("--ssh-key", type=str, default=None)
    dpdk_p.add_argument("--ssh-proxy-jump", type=str, default=None)
    dpdk_p.add_argument("--corpus", type=str, default="corpus")

    ask_p = subparsers.add_parser("ask", help="Universal 1-Call Zero-Stop Intent Gateway with forgiving C/C++ expressions & auto-heal PID (0.00ms stop)")
    ask_p.add_argument("-q", "--question", type=str, required=True, help="C/C++ expression or natural-language diagnostic question")
    ask_p.add_argument("-p", "--pid", type=int, default=None, help="Optional target PID (auto-resolved if omitted)")
    ask_p.add_argument("-d", "--debug-image", "--companion-elf", dest="debug_image", type=str, default=None, help="Optional companion ELF (auto-discovered from /proc/<pid>/exe if omitted)")
    ask_p.add_argument("--process-name", type=str, default=None)
    ask_p.add_argument("--remote-host", type=str, default=None)
    ask_p.add_argument("--ssh-user", type=str, default=None)
    ask_p.add_argument("--ssh-port", type=int, default=22)
    ask_p.add_argument("--ssh-key", type=str, default=None)
    ask_p.add_argument("--ssh-proxy-jump", type=str, default=None)
    ask_p.add_argument("--corpus", type=str, default="corpus")

    coerce_p = subparsers.add_parser("coerce-expr", help="Forgiving C/C++ Expression Auto-Coercer (. <-> ->, bare member promotion, symbol typos)")
    coerce_p.add_argument("-e", "--expression", type=str, required=True)
    coerce_p.add_argument("-p", "--pid", type=int, default=None)
    coerce_p.add_argument("-d", "--debug-image", "--companion-elf", dest="debug_image", type=str, default=None)
    coerce_p.add_argument("--corpus", type=str, default="corpus")

    sc_p = subparsers.add_parser("smart-compact", help="LLM token-budgeted anomaly-first smart compactor & cursor paginator (0.00ms stop)")
    sc_p.add_argument("-q", "--query", type=str, default="*gpMem")
    sc_p.add_argument("-m", "--mode", type=str, default="auto", choices=["auto", "pool", "eval", "ask"])
    sc_p.add_argument("-p", "--pid", type=int, default=None)
    sc_p.add_argument("-d", "--debug-image", "--companion-elf", dest="debug_image", type=str, default=None)
    sc_p.add_argument("--max-tokens", type=int, default=800)
    sc_p.add_argument("--offset", dest="cursor_offset", type=int, default=0)
    sc_p.add_argument("--page-size", type=int, default=16)
    sc_p.add_argument("--corpus", type=str, default="corpus")

    be_p = subparsers.add_parser("batch-exec", help="1-Call Multi-Tool Composite Batch Macro Executor (0.00ms stop)")
    be_p.add_argument("--steps-json", type=str, required=True, help="JSON list of step objects")
    be_p.add_argument("-p", "--pid", type=int, default=None)
    be_p.add_argument("-d", "--debug-image", "--companion-elf", dest="debug_image", type=str, default=None)
    be_p.add_argument("--corpus", type=str, default="corpus")

    vh_p = subparsers.add_parser("verify-hypothesis", help="Declarative multi-assertion hypothesis verifier (0.00ms stop)")
    vh_p.add_argument("--hypothesis", type=str, required=True)
    vh_p.add_argument("-a", "--assertions", type=str, required=True, help="Comma-separated assertions e.g. 'gpMem.active_buffers>=2,buffers[5].seq==5005'")
    vh_p.add_argument("--report-html", dest="report_html_path", type=str, default=None, help="Optional output path for standalone Zero-CDN HTML verification report")
    vh_p.add_argument("-p", "--pid", type=int, default=None)
    vh_p.add_argument("-d", "--debug-image", "--companion-elf", dest="debug_image", type=str, default=None)
    vh_p.add_argument("--corpus", type=str, default="corpus")

    er_p = subparsers.add_parser("export-report", help="1-Call Zero-Stop Incident Report & Remediation Exporter")
    er_p.add_argument("--title", type=str, default="dynamicState Zero-Stop Runtime Incident Report")
    er_p.add_argument("--hypothesis", type=str, default=None)
    er_p.add_argument("-a", "--assertions", type=str, default=None)
    er_p.add_argument("-o", "--output", dest="output_path", type=str, default=None)
    er_p.add_argument("--report-html", dest="report_html_path", type=str, default=None, help="Optional output path for standalone Zero-CDN HTML incident report")
    er_p.add_argument("-p", "--pid", type=int, default=None)
    er_p.add_argument("-d", "--debug-image", "--companion-elf", dest="debug_image", type=str, default=None)
    er_p.add_argument("--corpus", type=str, default="corpus")

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
            init_res = mgr.start_investigation(
                goal=args.goal,
                snapshot_id=args.snapshot,
                memory_snapshot_path=args.memory_snapshot,
                pid=args.pid,
                debug_image=args.debug_image,
                authorize_target=args.authorize_target,
            )
            inv_id = init_res.get("investigation_id")
            if inv_id and inv_id in mgr.sessions:
                report = mgr.generate_report(inv_id)
            else:
                report = init_res

            sanitized_out = None
            if args.output:
                sanitized_out, out_err = sanitize_report_output_path(args.output, file_type="investigation JSON report")
                if out_err:
                    print(f"WARNING: {out_err}", file=sys.stderr)
                elif sanitized_out:
                    try:
                        os.makedirs(os.path.dirname(sanitized_out), exist_ok=True)
                        with open(sanitized_out, "w", encoding="utf-8") as f:
                            json.dump(report, f, indent=2)
                        if not args.json:
                            print(f"Investigation report saved to {sanitized_out}")
                    except OSError as os_err:
                        print(f"WARNING: Failed to write report to {sanitized_out}: {os_err}", file=sys.stderr)

            if getattr(args, "report_html_path", None) and report.get("report_html"):
                sanitized_html, html_err = sanitize_report_output_path(args.report_html_path, file_type="HTML report")
                if html_err:
                    print(f"WARNING: {html_err}", file=sys.stderr)
                elif sanitized_html:
                    if sanitized_out and os.path.realpath(sanitized_out) == os.path.realpath(sanitized_html):
                        print(
                            f"WARNING: Refusing to overwrite JSON output path '{sanitized_out}' with HTML report. Specify distinct paths.",
                            file=sys.stderr,
                        )
                    else:
                        try:
                            os.makedirs(os.path.dirname(sanitized_html), exist_ok=True)
                            with open(sanitized_html, "w", encoding="utf-8") as f:
                                f.write(report["report_html"])
                            if not args.json:
                                print(f"HTML investigation report saved to {sanitized_html}")
                        except OSError as os_err:
                            print(f"WARNING: Failed to write HTML report to {sanitized_html}: {os_err}", file=sys.stderr)

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



    elif args.command == "connect":
        from .watch_session import WatchSessionManager
        from .debug_image import inspect_elf
        from .dwarf_indexer import DwarfIndexer
        wm = WatchSessionManager(corpus_dir=args.corpus)
        adapter = wm._resolve_adapter(
            pid=args.pid or 1,
            remote_host=args.remote_host,
            ssh_user=args.ssh_user,
            ssh_port=args.ssh_port,
            ssh_key=args.ssh_key,
            ssh_proxy_jump=args.ssh_proxy_jump,
        )
        dbg_ident = inspect_elf(args.debug_image)
        pid = args.pid
        if (not pid or pid <= 0) and args.process_name:
            matches = adapter.find_processes(process_name=args.process_name, companion_build_id=dbg_ident.build_id)
            if not matches:
                print(json.dumps({"success": False, "error": f"No process matching '{args.process_name}'"}, indent=2))
                sys.exit(1)
            pid = int(matches[0]["pid"])
        if not pid or pid <= 0:
            print(json.dumps({"success": False, "error": "Valid --pid or --process-name required"}, indent=2))
            sys.exit(1)
        coll_info = adapter.ensure_remote_collector() if (args.auto_deploy_collector and hasattr(adapter, "ensure_remote_collector")) else None
        map_data = wm.get_memory_map_and_threads(pid=pid, companion_elf_path=args.debug_image, adapter=adapter)
        idx = DwarfIndexer.get_index(args.debug_image)
        rec_syms = idx.search_symbols(limit=12, smart_rank=True, load_bias=map_data.get("base_address_int", 0), is_dyn=(idx.elf_type == "ET_DYN"))
        print(json.dumps({
            "success": True,
            "pid": pid,
            "target_host": adapter.target_host(),
            "is_remote": adapter.is_remote(),
            "build_id": dbg_ident.build_id,
            "load_bias": map_data.get("load_bias"),
            "collector_deployment": coll_info,
            "recommended_symbols": rec_syms,
        }, indent=2, ensure_ascii=False))
        sys.exit(0)

    elif args.command == "eval":
        from .watch_session import WatchSessionManager
        wm = WatchSessionManager(corpus_dir=args.corpus)
        exprs = [e.strip() for e in args.expr.split(",") if e.strip()]
        res = wm.evaluate_symbol_paths(
            pid=args.pid,
            companion_elf_path=args.debug_image,
            expressions=exprs,
            remote_host=args.remote_host,
            ssh_user=args.ssh_user,
            ssh_port=args.ssh_port,
            ssh_key=args.ssh_key,
            ssh_proxy_jump=args.ssh_proxy_jump,
        )
        print(json.dumps({"success": True, **res}, indent=2, ensure_ascii=False))
        sys.exit(0)

    elif args.command == "diff":
        from .watch_session import WatchSessionManager
        wm = WatchSessionManager(corpus_dir=args.corpus)
        exprs = [e.strip() for e in args.expr.split(",") if e.strip()] if args.expr else None
        res = wm.capture_and_diff_expressions(
            pid=args.pid,
            companion_elf_path=args.debug_image,
            expressions=exprs,
            wait_ms=args.wait_ms,
            remote_host=args.remote_host,
            ssh_user=args.ssh_user,
            ssh_port=args.ssh_port,
            ssh_key=args.ssh_key,
            ssh_proxy_jump=args.ssh_proxy_jump,
        )
        print(json.dumps({"success": True, **res}, indent=2, ensure_ascii=False))
        sys.exit(0)

    elif args.command == "pool-map":
        from .watch_session import WatchSessionManager
        wm = WatchSessionManager(corpus_dir=args.corpus)
        res = wm.scan_memory_pool_or_array(
            pid=args.pid,
            companion_elf_path=args.debug_image,
            base_expression=args.expr,
            count=args.count,
            status_field=args.status_field,
            remote_host=args.remote_host,
            ssh_user=args.ssh_user,
            ssh_port=args.ssh_port,
            ssh_key=args.ssh_key,
            ssh_proxy_jump=args.ssh_proxy_jump,
        )
        print(json.dumps({"success": True, **res}, indent=2, ensure_ascii=False))
        sys.exit(0)

    elif args.command == "find-owner":
        from .watch_session import WatchSessionManager
        wm = WatchSessionManager(corpus_dir=args.corpus)
        res = wm.find_symbol_owners_and_threads(
            pid=args.pid,
            companion_elf_path=args.debug_image,
            target_expression=args.expr,
            remote_host=args.remote_host,
            ssh_user=args.ssh_user,
            ssh_port=args.ssh_port,
            ssh_key=args.ssh_key,
            ssh_proxy_jump=args.ssh_proxy_jump,
        )
        print(json.dumps({"success": True, **res}, indent=2, ensure_ascii=False))
        sys.exit(0)

    elif args.command == "workspace":
        from .agent_runtime import AgentRuntime
        from .web.server import run_server, run_server_loop
        from .web.workspace import get_workspace_static_dir
        corpus_dir = os.path.abspath(args.corpus)
        os.makedirs(corpus_dir, exist_ok=True)
        rt = AgentRuntime(corpus_dir=corpus_dir)
        rt.observation_mode = "LOW_IMPACT"
        srv = run_server(runtime=rt, host=args.host, port=args.port, static_dir=get_workspace_static_dir())
        print(f"dynamicState Trace Workspace running at http://{args.host}:{args.port}")
        sys.stdout.flush()
        run_server_loop(srv)
        sys.exit(0)

    elif args.command == "recipe":
        from .watch_session import WatchSessionManager
        wm = WatchSessionManager(corpus_dir=args.corpus)
        exprs = [e.strip() for e in args.expr.split(",") if e.strip()] if args.expr else None
        if args.name == "save_baseline":
            res = wm.save_golden_baseline(
                pid=args.pid,
                companion_elf_path=args.debug_image,
                label=args.label,
                expressions=exprs,
                remote_host=args.remote_host,
                ssh_user=args.ssh_user,
                ssh_port=args.ssh_port,
                ssh_key=args.ssh_key,
                ssh_proxy_jump=args.ssh_proxy_jump,
            )
        elif args.name == "compare_baseline":
            if not args.baseline_id:
                print(json.dumps({"success": False, "error": "--baseline-id is required for compare_baseline"}, indent=2))
                sys.exit(1)
            res = wm.compare_with_golden_baseline(
                baseline_id=args.baseline_id,
                pid=args.pid,
                companion_elf_path=args.debug_image,
                remote_host=args.remote_host,
                ssh_user=args.ssh_user,
                ssh_port=args.ssh_port,
                ssh_key=args.ssh_key,
                ssh_proxy_jump=args.ssh_proxy_jump,
            )
        else:
            res = wm.run_diagnostic_recipe(
                recipe=args.name,
                pid=args.pid,
                companion_elf_path=args.debug_image,
                expressions=exprs,
                duration_ms=args.duration_ms,
                interval_ms=args.interval_ms,
                remote_host=args.remote_host,
                ssh_user=args.ssh_user,
                ssh_port=args.ssh_port,
                ssh_key=args.ssh_key,
                ssh_proxy_jump=args.ssh_proxy_jump,
            )
        print(json.dumps({"success": True, **res}, indent=2, ensure_ascii=False))
        sys.exit(0)


    elif args.command == "watch-until":
        from .watch_session import WatchSessionManager
        wm = WatchSessionManager(corpus_dir=args.corpus)
        res = wm.watch_until_condition(
            pid=args.pid,
            companion_elf_path=args.debug_image,
            condition_expression=args.condition,
            poll_interval_ms=args.poll_ms,
            timeout_ms=args.timeout_ms,
            hold_duration_ms=args.hold_ms,
            remote_host=args.remote_host,
            ssh_user=args.ssh_user,
            ssh_port=args.ssh_port,
            ssh_key=args.ssh_key,
            ssh_proxy_jump=args.ssh_proxy_jump,
        )
        print(json.dumps({"success": True, **res}, indent=2, ensure_ascii=False))
        sys.exit(0)

    elif args.command == "traverse-list":
        from .watch_session import WatchSessionManager
        wm = WatchSessionManager(corpus_dir=args.corpus)
        res = wm.traverse_linked_structure(
            pid=args.pid,
            companion_elf_path=args.debug_image,
            head_expression=args.expr,
            next_field=args.next_field,
            max_depth=args.max_depth,
            remote_host=args.remote_host,
            ssh_user=args.ssh_user,
            ssh_port=args.ssh_port,
            ssh_key=args.ssh_key,
            ssh_proxy_jump=args.ssh_proxy_jump,
        )
        print(json.dumps({"success": True, **res}, indent=2, ensure_ascii=False))
        sys.exit(0)

    elif args.command == "callstacks":
        from .watch_session import WatchSessionManager
        wm = WatchSessionManager(corpus_dir=args.corpus)
        res = wm.inspect_thread_callstacks_and_locks(
            pid=args.pid,
            companion_elf_path=args.debug_image,
            tid=args.tid,
            remote_host=args.remote_host,
            ssh_user=args.ssh_user,
            ssh_port=args.ssh_port,
            ssh_key=args.ssh_key,
            ssh_proxy_jump=args.ssh_proxy_jump,
        )
        print(json.dumps({"success": True, **res}, indent=2, ensure_ascii=False))
        sys.exit(0)

    elif args.command == "audit":
        from .watch_session import WatchSessionManager
        wm = WatchSessionManager(corpus_dir=args.corpus)
        exprs = [e.strip() for e in args.expr.split(",") if e.strip()] if args.expr else None
        res = wm.audit_memory_integrity(
            pid=args.pid,
            companion_elf_path=args.debug_image,
            target_expressions=exprs,
            remote_host=args.remote_host,
            ssh_user=args.ssh_user,
            ssh_port=args.ssh_port,
            ssh_key=args.ssh_key,
            ssh_proxy_jump=args.ssh_proxy_jump,
        )
        print(json.dumps({"success": True, **res}, indent=2, ensure_ascii=False))
        sys.exit(0)

    elif args.command == "resolve-func":
        from .watch_session import WatchSessionManager
        wm = WatchSessionManager(corpus_dir=args.corpus)
        exprs = [e.strip() for e in args.expr.split(",") if e.strip()]
        res = wm.resolve_code_pointers(
            pid=args.pid,
            companion_elf_path=args.debug_image,
            expressions=exprs,
            remote_host=args.remote_host,
            ssh_user=args.ssh_user,
            ssh_port=args.ssh_port,
            ssh_key=args.ssh_key,
            ssh_proxy_jump=args.ssh_proxy_jump,
        )
        print(json.dumps({"success": True, **res}, indent=2, ensure_ascii=False))
        sys.exit(0)

    elif args.command == "inspect-shm":
        from .watch_session import WatchSessionManager
        wm = WatchSessionManager(corpus_dir=args.corpus)
        res = wm.inspect_shared_memory_ipc(
            pid=args.pid,
            companion_elf_path=args.debug_image,
            cast_type=args.cast_type,
            address=args.address,
            shm_name=args.shm_name,
            remote_host=args.remote_host,
            ssh_user=args.ssh_user,
            ssh_port=args.ssh_port,
            ssh_key=args.ssh_key,
            ssh_proxy_jump=args.ssh_proxy_jump,
        )
        print(json.dumps({"success": True, **res}, indent=2, ensure_ascii=False))
        sys.exit(0)


    elif args.command == "frame-locals":
        from .watch_session import WatchSessionManager
        wm = WatchSessionManager(corpus_dir=args.corpus)
        res = wm.inspect_thread_locals_and_frame_vars(
            pid=args.pid,
            companion_elf_path=args.debug_image,
            tid=args.tid,
            remote_host=args.remote_host,
            ssh_user=args.ssh_user,
            ssh_port=args.ssh_port,
            ssh_key=args.ssh_key,
            ssh_proxy_jump=args.ssh_proxy_jump,
        )
        print(json.dumps({"success": True, **res}, indent=2, ensure_ascii=False))
        sys.exit(0)

    elif args.command == "auto-triage":
        from .watch_session import WatchSessionManager
        wm = WatchSessionManager(corpus_dir=args.corpus)
        res = wm.auto_triage_incident(
            pid=args.pid,
            companion_elf_path=args.debug_image,
            remote_host=args.remote_host,
            ssh_user=args.ssh_user,
            ssh_port=args.ssh_port,
            ssh_key=args.ssh_key,
            ssh_proxy_jump=args.ssh_proxy_jump,
        )
        print(json.dumps({"success": True, **res}, indent=2, ensure_ascii=False))
        sys.exit(0)


    elif args.command == "ipc-pipeline":
        from .watch_session import WatchSessionManager
        wm = WatchSessionManager(corpus_dir=args.corpus)
        res = wm.trace_ipc_pipeline(
            pid=args.pid,
            companion_elf_path=args.debug_image,
            cast_type=args.cast_type,
            address=args.address,
            shm_name=args.shm_name,
            remote_host=args.remote_host,
            ssh_user=args.ssh_user,
            ssh_port=args.ssh_port,
            ssh_key=args.ssh_key,
            ssh_proxy_jump=args.ssh_proxy_jump,
        )
        print(json.dumps({"success": True, **res}, indent=2, ensure_ascii=False))
        sys.exit(0)

    elif args.command == "scan-heap":
        from .watch_session import WatchSessionManager
        wm = WatchSessionManager(corpus_dir=args.corpus)
        res = wm.scan_heap_objects(
            pid=args.pid,
            companion_elf_path=args.debug_image,
            class_filter=args.class_filter,
            remote_host=args.remote_host,
            ssh_user=args.ssh_user,
            ssh_port=args.ssh_port,
            ssh_key=args.ssh_key,
            ssh_proxy_jump=args.ssh_proxy_jump,
        )
        print(json.dumps({"success": True, **res}, indent=2, ensure_ascii=False))
        sys.exit(0)

    elif args.command == "dependency-graph":
        from .watch_session import WatchSessionManager
        wm = WatchSessionManager(corpus_dir=args.corpus)
        res = wm.build_dependency_graph(
            pid=args.pid,
            companion_elf_path=args.debug_image,
            remote_host=args.remote_host,
            ssh_user=args.ssh_user,
            ssh_port=args.ssh_port,
            ssh_key=args.ssh_key,
            ssh_proxy_jump=args.ssh_proxy_jump,
        )
        print(json.dumps({"success": True, **res}, indent=2, ensure_ascii=False))
        sys.exit(0)

    elif args.command == "correlate-source":
        from .watch_session import WatchSessionManager
        wm = WatchSessionManager(corpus_dir=args.corpus)
        res = wm.correlate_source_and_state(
            pid=args.pid,
            companion_elf_path=args.debug_image,
            source_location=args.source_location,
            tid=args.tid,
            context_lines=args.context_lines,
            remote_host=args.remote_host,
            ssh_user=args.ssh_user,
            ssh_port=args.ssh_port,
            ssh_key=args.ssh_key,
            ssh_proxy_jump=args.ssh_proxy_jump,
        )
        print(json.dumps({"success": True, **res}, indent=2, ensure_ascii=False))
        sys.exit(0)

    elif args.command == "investigate-symptom":
        from .watch_session import WatchSessionManager
        wm = WatchSessionManager(corpus_dir=args.corpus)
        res = wm.investigate_symptom(
            pid=args.pid,
            companion_elf_path=args.debug_image,
            symptom_query=args.symptom_query,
            remote_host=args.remote_host,
            ssh_user=args.ssh_user,
            ssh_port=args.ssh_port,
            ssh_key=args.ssh_key,
            ssh_proxy_jump=args.ssh_proxy_jump,
        )
        print(json.dumps({"success": True, **res}, indent=2, ensure_ascii=False))
        sys.exit(0)

    elif args.command == "hotspots":
        from .watch_session import WatchSessionManager
        wm = WatchSessionManager(corpus_dir=args.corpus)
        res = wm.sample_statistical_hotspots(
            pid=args.pid,
            companion_elf_path=args.debug_image,
            samples_count=args.samples_count,
            interval_ms=args.interval_ms,
            remote_host=args.remote_host,
            ssh_user=args.ssh_user,
            ssh_port=args.ssh_port,
            ssh_key=args.ssh_key,
            ssh_proxy_jump=args.ssh_proxy_jump,
        )
        print(json.dumps({"success": True, **res}, indent=2, ensure_ascii=False))
        sys.exit(0)

    elif args.command == "fuzzy-resolve":
        from .watch_session import WatchSessionManager
        wm = WatchSessionManager(corpus_dir=args.corpus)
        res = wm.resolve_fuzzy_symbol_intent(
            pid=args.pid,
            companion_elf_path=args.debug_image,
            natural_query=args.natural_query,
            limit=args.limit,
            remote_host=args.remote_host,
            ssh_user=args.ssh_user,
            ssh_port=args.ssh_port,
            ssh_key=args.ssh_key,
            ssh_proxy_jump=args.ssh_proxy_jump,
        )
        print(json.dumps({"success": True, **res}, indent=2, ensure_ascii=False))
        sys.exit(0)

    elif args.command == "flight-recorder":
        from .watch_session import WatchSessionManager
        wm = WatchSessionManager(corpus_dir=args.corpus)
        res = wm.flight_recorder_time_machine(
            pid=args.pid,
            companion_elf_path=args.debug_image,
            frames_count=args.frames_count,
            interval_ms=args.interval_ms,
            remote_host=args.remote_host,
            ssh_user=args.ssh_user,
            ssh_port=args.ssh_port,
            ssh_key=args.ssh_key,
            ssh_proxy_jump=args.ssh_proxy_jump,
        )
        print(json.dumps({"success": True, **res}, indent=2, ensure_ascii=False))
        sys.exit(0)

    elif args.command == "behavioral-drift":
        from .watch_session import WatchSessionManager
        wm = WatchSessionManager(corpus_dir=args.corpus)
        res = wm.detect_behavioral_drift(
            pid=args.pid,
            companion_elf_path=args.debug_image,
            save_as_new_baseline=args.save_baseline,
            remote_host=args.remote_host,
            ssh_user=args.ssh_user,
            ssh_port=args.ssh_port,
            ssh_key=args.ssh_key,
            ssh_proxy_jump=args.ssh_proxy_jump,
        )
        print(json.dumps({"success": True, **res}, indent=2, ensure_ascii=False))
        sys.exit(0)

    elif args.command == "tls-vars":
        from .watch_session import WatchSessionManager
        wm = WatchSessionManager(corpus_dir=args.corpus)
        v_names = [x.strip() for x in args.variable_names.split(",") if x.strip()] if args.variable_names else None
        res = wm.inspect_thread_local_storage(
            pid=args.pid,
            companion_elf_path=args.debug_image,
            tid=args.tid,
            variable_names=v_names,
            remote_host=args.remote_host,
            ssh_user=args.ssh_user,
            ssh_port=args.ssh_port,
            ssh_key=args.ssh_key,
            ssh_proxy_jump=args.ssh_proxy_jump,
        )
        print(json.dumps({"success": True, **res}, indent=2, ensure_ascii=False))
        sys.exit(0)

    elif args.command == "verify-consistency":
        from .watch_session import WatchSessionManager
        wm = WatchSessionManager(corpus_dir=args.corpus)
        exprs = [x.strip() for x in args.expressions.split(",") if x.strip()] if args.expressions else None
        res = wm.verify_concurrent_read_consistency(
            pid=args.pid,
            companion_elf_path=args.debug_image,
            expressions=exprs,
            retries=args.retries,
            inter_read_delay_ms=args.inter_read_delay_ms,
            remote_host=args.remote_host,
            ssh_user=args.ssh_user,
            ssh_port=args.ssh_port,
            ssh_key=args.ssh_key,
            ssh_proxy_jump=args.ssh_proxy_jump,
        )
        print(json.dumps({"success": True, **res}, indent=2, ensure_ascii=False))
        sys.exit(0)

    elif args.command == "dpdk-lcores":
        from .watch_session import WatchSessionManager
        wm = WatchSessionManager(corpus_dir=args.corpus)
        r_exprs = [x.strip() for x in args.ring_expressions.split(",") if x.strip()] if args.ring_expressions else None
        s_exprs = [x.strip() for x in args.spinlock_expressions.split(",") if x.strip()] if args.spinlock_expressions else None
        res = wm.inspect_dpdk_lcores_and_rings(
            pid=args.pid,
            companion_elf_path=args.debug_image,
            sample_window_ms=args.sample_window_ms,
            ring_expressions=r_exprs,
            spinlock_expressions=s_exprs,
            remote_host=args.remote_host,
            ssh_user=args.ssh_user,
            ssh_port=args.ssh_port,
            ssh_key=args.ssh_key,
            ssh_proxy_jump=args.ssh_proxy_jump,
        )
        print(json.dumps({"success": True, **res}, indent=2, ensure_ascii=False))
        sys.exit(0)

    elif args.command == "ask":
        from .watch_session import WatchSessionManager
        wm = WatchSessionManager(corpus_dir=args.corpus)
        res = wm.ask_runtime_question(
            question=args.question,
            pid=args.pid,
            companion_elf_path=args.debug_image,
            process_name=args.process_name,
            remote_host=args.remote_host,
            ssh_user=args.ssh_user,
            ssh_port=args.ssh_port,
            ssh_key=args.ssh_key,
            ssh_proxy_jump=args.ssh_proxy_jump,
        )
        print(json.dumps({"success": True, **res}, indent=2, ensure_ascii=False))
        sys.exit(0)

    elif args.command == "coerce-expr":
        from .watch_session import WatchSessionManager
        from .dwarf_indexer import DwarfIndexer
        wm = WatchSessionManager(corpus_dir=args.corpus)
        ctx = wm.resolve_target_context(pid=args.pid, companion_elf_path=args.debug_image)
        primary_elf, _ = wm._split_companion_elf_paths(ctx["companion_elf_path"])
        idx = DwarfIndexer.get_index(primary_elf)
        res = wm.coerce_and_resolve_expression(idx=idx, raw_expr=args.expression)
        res_clean = {k: v for k, v in res.items() if k != "ops"}
        print(json.dumps({"success": True, "pid": ctx["pid"], "companion_elf": ctx["companion_elf_path"], **res_clean}, indent=2, ensure_ascii=False))
        sys.exit(0)

    elif args.command == "smart-compact":
        from .watch_session import WatchSessionManager
        wm = WatchSessionManager(corpus_dir=args.corpus)
        res = wm.smart_compact_query(
            query_or_expression=args.query,
            mode=args.mode,
            pid=args.pid,
            companion_elf_path=args.debug_image,
            max_tokens=args.max_tokens,
            cursor_offset=args.cursor_offset,
            page_size=args.page_size,
        )
        print(json.dumps({"success": True, **res}, indent=2, ensure_ascii=False))
        sys.exit(0)

    elif args.command == "batch-exec":
        from .watch_session import WatchSessionManager
        wm = WatchSessionManager(corpus_dir=args.corpus)
        steps_list = json.loads(args.steps_json)
        res = wm.execute_batch_macro(
            steps=steps_list,
            pid=args.pid,
            companion_elf_path=args.debug_image,
        )
        print(json.dumps({"success": True, **res}, indent=2, ensure_ascii=False))
        sys.exit(0)

    elif args.command == "verify-hypothesis":
        from .watch_session import WatchSessionManager
        wm = WatchSessionManager(corpus_dir=args.corpus)
        a_list = [x.strip() for x in args.assertions.split(",") if x.strip()]
        res = wm.verify_runtime_hypothesis(
            hypothesis=args.hypothesis,
            assertions=a_list,
            pid=args.pid,
            companion_elf_path=args.debug_image,
            report_html_path=getattr(args, "report_html_path", None),
        )
        if res.get("save_html_error"):
            print(f"WARNING: {res['save_html_error']}", file=sys.stderr)
        print(json.dumps({"success": True, **res}, indent=2, ensure_ascii=False))
        sys.exit(0)

    elif args.command == "export-report":
        from .watch_session import WatchSessionManager
        wm = WatchSessionManager(corpus_dir=args.corpus)
        a_list = [x.strip() for x in args.assertions.split(",") if x.strip()] if args.assertions else None
        res = wm.export_incident_report(
            title=args.title,
            hypothesis=args.hypothesis,
            assertions=a_list,
            output_path=args.output_path,
            report_html_path=getattr(args, "report_html_path", None),
            pid=args.pid,
            companion_elf_path=args.debug_image,
        )
        if res.get("save_error"):
            print(f"WARNING: {res['save_error']}", file=sys.stderr)
        if res.get("save_html_error"):
            print(f"WARNING: {res['save_html_error']}", file=sys.stderr)
        print(json.dumps({"success": True, **res}, indent=2, ensure_ascii=False))
        sys.exit(0)


if __name__ == "__main__":
    main()
