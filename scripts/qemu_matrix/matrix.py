"""Matrix orchestration + CLI (IMP-014).

    python3 -m scripts.qemu_matrix list
    python3 -m scripts.qemu_matrix prepare [entry ...]   # downloads + builds images into the cache (explicit only)
    python3 -m scripts.qemu_matrix run [entry ...] [--out DIR] [--timeout S]
    python3 -m scripts.qemu_matrix summary DIR            # (re)write the markdown table from result JSONs
"""
from __future__ import annotations

import argparse
import atexit
import json
import os
import platform
import shutil
import signal
import subprocess
import sys
import threading
import time
from typing import Any, Dict, List, Optional

from . import build_targets, checks, entries, guest as guest_mod, images, results, vm

_ACTIVE: List[guest_mod.Guest] = []


def _cleanup_all(*_a) -> None:
    for g in list(_ACTIVE):
        try:
            g.stop()
        except Exception:  # noqa: BLE001
            pass


atexit.register(_cleanup_all)


def _on_signal(signum, _frame):
    _cleanup_all()
    raise SystemExit(128 + signum)


def host_info() -> Dict[str, Any]:
    def ver(cmd: List[str]) -> str:
        try:
            return subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout.splitlines()[0]
        except Exception:  # noqa: BLE001
            return "unavailable"
    return {"machine": platform.machine(), "python": platform.python_version(),
            "kernel": platform.release(), "kvm_available": os.path.exists("/dev/kvm"),
            "qemu_aarch64": ver(["qemu-system-aarch64", "--version"]),
            "cross_cc": {e["cc"]: ver([e["cc"], "--version"]) for e in {v["cc"]: v for v in entries.ENTRIES.values()}.values()}}


def missing_prerequisites(name: str) -> List[str]:
    e = entries.ENTRIES[name]
    miss = []
    if not shutil.which(e["qemu_bin"]):
        miss.append(f"{e['qemu_bin']} not installed")
    if not shutil.which(e["cc"]):
        miss.append(f"{e['cc']} not installed")
    if not shutil.which("ssh") or not shutil.which("ssh-keygen"):
        miss.append("openssh-client not installed")
    dist = os.path.join(build_targets.REPO, "target", "collector", "dist", e["collector_arch"], "dynamicstate-collector")
    if not os.path.isfile(dist):
        miss.append(f"collector binary missing: run `make -C target/collector dist` ({dist})")
    if not entries.images_ready(name):
        miss.append(f"guest images not in cache ({images.cache_dir()}): run `python3 -m scripts.qemu_matrix prepare {name}`")
    return miss


def run_entry(name: str, out_dir: str, entry_timeout_s: float = 1500.0, host_ref: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    e = entries.ENTRIES[name]
    doc = results.new_result(e)
    t_start = time.monotonic()
    old_term = None
    if threading.current_thread() is threading.main_thread():
        # also when called from a test runner / timeout(1): SIGTERM must still tear the guest down
        old_term = signal.signal(signal.SIGTERM, _on_signal)
    g: Optional[guest_mod.Guest] = None
    watchdog: Optional[threading.Timer] = None
    work = None
    try:
        miss = missing_prerequisites(name)
        if miss:
            raise RuntimeError("prerequisites missing: " + "; ".join(miss))
        targets = build_targets.build_entry_targets(e, os.path.join(entries.entry_cache(name), "targets"))
        g = guest_mod.Guest(name)
        work = g.work
        _ACTIVE.append(g)
        watchdog = threading.Timer(entry_timeout_s, lambda: g.stop())
        watchdog.daemon = True
        watchdog.start()
        g.start()
        rc, un, _ = g.ssh("uname -srm; busybox 2>&1 | head -1")
        doc["guest"] = {"uname": un.strip().splitlines(), "boot_to_ssh_s": g.boot_info.get("ssh_ready_after_s"),
                        "vcpus": 1, "mem_mb": e["mem_mb"], "cpu_model": e["cpu"], "machine": e["machine"],
                        "accel": "tcg", "packages": _read_packages(name)}
        ctx = checks.Ctx(g, e, targets, host_ref or {"available": False, "locks": sorted(checks.EXPECTED_LOCKS)})
        ctx.start_memtarget()
        out = doc["checks"]
        out.append(checks.guarded("C1_collector_deploy_and_slice", "deploy", lambda: checks.c1_deploy_and_slice(ctx)))
        out.append(checks.guarded("C1b_noexec_fallback_location", "noexec", lambda: checks.c1b_noexec_fallback(ctx)))
        out.append(checks.guarded("C6_process_discovery_and_identity", "discovery", lambda: checks.c6_discovery(ctx)))
        if ctx.collector_info.get("deployed"):
            out.append(checks.guarded("C2a_daemon_channel", "daemon", lambda: checks.c2a_daemon_channel(ctx)))
        else:
            out.append(results.check("C2a_daemon_channel", "daemon channel", results.SKIPPED, "collector not deployed (C1)"))
        out.append(checks.guarded("C2b_no_collector_fallback", "fallback", lambda: checks.c2b_fallback(ctx)))
        out.append(checks.guarded("C3_abi_detection", "abi", lambda: checks.c3_abi(ctx)))
        ctx.start_deadlock()
        holder: Dict[str, Any] = {}

        def _dl() -> Dict[str, Any]:
            holder["run"] = checks.collect_deadlock(ctx)
            return checks.c4a_deadlock(ctx, holder["run"])
        out.append(checks.guarded("C4a_deadlock_diagnosis", "deadlock", _dl))
        out.append(checks.guarded("C4b_glibc_only_gating", "gating", lambda: checks.c4b_gating(ctx)))
        out.append(checks.guarded("C4c_futex_syscall_names", "syscall", lambda: checks.c4c_syscall_names(ctx)))
        out.append(checks.guarded("C4d_diagnose_entry_point", "diagnose", lambda: checks.c4d_diagnose_entry_point(ctx)))
        if "run" in holder:
            out.append(checks.guarded("C5_collection_cost", "cost", lambda: checks.c5_cost(ctx, holder["run"])))
        else:
            out.append(results.check("C5_collection_cost", "cost", results.SKIPPED, "deadlock collection failed (C4a)"))
        order = {c: i for i, c in enumerate(results.CHECK_IDS)}
        out.sort(key=lambda c: order.get(c["id"], 99))
        for c in out:
            c["name"] = _CHECK_NAMES.get(c["id"], c["name"])
    except BaseException as exc:  # noqa: BLE001 - always record, always tear down
        doc["infrastructure_error"] = f"{type(exc).__name__}: {exc}"
        if g is not None and g.vm is not None:
            doc["infrastructure_error"] += "\n--- console tail ---\n" + g.vm.console_tail(1500)
    finally:
        if old_term is not None:
            signal.signal(signal.SIGTERM, old_term)
        if watchdog is not None:
            watchdog.cancel()
        if g is not None:
            doc["teardown"] = g.stop()
            doc["guest"].setdefault("qemu_args", [a for a in (g.boot_info.get("qemu_args") or [])])
            if g in _ACTIVE:
                _ACTIVE.remove(g)
        if work and os.path.isdir(work):
            shutil.rmtree(work, ignore_errors=True)
        doc["duration_s"] = round(time.monotonic() - t_start, 1)
        doc["overall"] = results.overall(doc["checks"], doc["infrastructure_error"])
        left = vm.leftover_qemu_processes()
        doc["teardown"]["leftover_qemu_processes"] = left
        os.makedirs(out_dir, exist_ok=True)
        with open(os.path.join(out_dir, f"{name}.json"), "w") as f:
            json.dump(doc, f, indent=1, sort_keys=False, default=str)
            f.write("\n")
    return doc


_CHECK_NAMES = {
    "C1_collector_deploy_and_slice": "Collector deploys (arch, static, version) + slice read returns expected bytes",
    "C1b_noexec_fallback_location": "Deploy falls back to another location when the primary is noexec",
    "C2a_daemon_channel": "Daemon channel: N reads, one collector process",
    "C2b_no_collector_fallback": "No-collector fallback with the guest's BusyBox dd/tail/head, unaligned ranges",
    "C3_abi_detection": "ABI detection via remote adapter (arch / word size / endianness / libc)",
    "C4a_deadlock_diagnosis": "Deadlock diagnosis vs. host result",
    "C4b_glibc_only_gating": "Remote heap walk (glibc allocator)",
    "C4c_futex_syscall_names": "futex waiters carry the right syscall name",
    "C4d_diagnose_entry_point": "diagnose() over SSH on the guest's deadlock fixture vs. host result",
    "C5_collection_cost": "Collection cost (wall time, remote commands)",
    "C6_process_discovery_and_identity": "Process discovery / identity / maps via BusyBox shell tools",
}


def _read_packages(name: str) -> List[str]:
    try:
        return open(os.path.join(entries.entry_cache(name), "packages.txt")).read().split()
    except OSError:
        return []


def markdown_summary(docs: List[Dict[str, Any]]) -> str:
    lines = ["| check | " + " | ".join(d["entry"] for d in docs) + " |",
             "|---|" + "---|" * len(docs)]
    for row in results.table_rows(docs):
        lines.append("| " + " | ".join([_CHECK_NAMES.get(row[0], row[0])] + [
            _cell(docs[i], row[0], row[i + 1]) for i in range(len(docs))]) + " |")
    lines.append("| overall | " + " | ".join(d["overall"] or "?" for d in docs) + " |")
    lines.append("| run time (s) | " + " | ".join(str(d.get("duration_s")) for d in docs) + " |")
    return "\n".join(lines) + "\n"


def _cell(doc: Dict[str, Any], cid: str, status: str) -> str:
    c = next((x for x in doc["checks"] if x["id"] == cid), None)
    if c and c.get("known_defect"):
        return f"{status} ({c['known_defect']})"
    return status


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="python3 -m scripts.qemu_matrix", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    p = sub.add_parser("prepare")
    p.add_argument("entries", nargs="*")
    r = sub.add_parser("run")
    r.add_argument("entries", nargs="*")
    r.add_argument("--out", default=os.path.join(build_targets.REPO, "qemu_matrix_results"))
    r.add_argument("--timeout", type=float, default=1500.0, help="per-entry wall-clock limit (s)")
    s = sub.add_parser("summary")
    s.add_argument("dir")
    b = sub.add_parser("board", help="run the checks against a real board (docs/EMBEDDED_BOARD_RUN.md)")
    b.add_argument("--host", required=True)
    b.add_argument("--port", type=int, default=22)
    b.add_argument("--user", default="root")
    b.add_argument("--key", required=True)
    b.add_argument("--arch", choices=["aarch64", "x86_64"], default="aarch64")
    b.add_argument("--cc", required=True, help="cross compiler for the board, e.g. aarch64-linux-gnu-gcc")
    b.add_argument("--board-name", required=True)
    b.add_argument("--notes", default="")
    b.add_argument("--uname-m", default=None, help="override expected `uname -m` (default aarch64 / x86_64)")
    b.add_argument("--workdir", default="/tmp", help="writable, exec-capable directory on the board")
    b.add_argument("--out", default="board_record")
    a = ap.parse_args(argv)
    if a.cmd == "board":
        from .board import run_board
        return run_board(a)
    names = [n for n in (getattr(a, "entries", None) or entries.entry_names())]
    for n in names:
        if n not in entries.ENTRIES:
            ap.error(f"unknown entry {n!r} (have: {', '.join(entries.entry_names())})")
    if a.cmd == "list":
        for n in entries.entry_names():
            print(f"{n}\t{entries.ENTRIES[n]['title']}\timages_ready={entries.images_ready(n)}")
        return 0
    if a.cmd == "prepare":
        for n in names:
            print(f"== preparing {n}", flush=True)
            entries.prepare_entry(n)
        with open(os.path.join(images.cache_dir(), "downloads.json")) as f:
            print(f"downloads recorded in {images.cache_dir()}/downloads.json ({len(json.load(f))} files)")
        return 0
    if a.cmd == "summary":
        docs = [json.load(open(os.path.join(a.dir, n + ".json"))) for n in entries.entry_names()
                if os.path.exists(os.path.join(a.dir, n + ".json"))]
        sys.stdout.write(markdown_summary(docs))
        return 0
    # run
    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGINT, _on_signal)
    ref = checks.host_reference()
    os.makedirs(a.out, exist_ok=True)
    with open(os.path.join(a.out, "host.json"), "w") as f:
        json.dump({"host": host_info(), "host_deadlock_reference": ref, "downloads": images.downloads_manifest()}, f, indent=1)
    docs = []
    for n in names:
        print(f"== running {n}", flush=True)
        d = run_entry(n, a.out, a.timeout, ref)
        docs.append(d)
        print(f"   {n}: {d['overall']} in {d['duration_s']}s" +
              (f" ({d['infrastructure_error'].splitlines()[0]})" if d["infrastructure_error"] else ""), flush=True)
    md = markdown_summary(docs)
    with open(os.path.join(a.out, "summary.md"), "w") as f:
        f.write(md)
    print(md)
    left = vm.leftover_qemu_processes()
    if left:
        print("WARNING: leftover qemu processes:", left)
        return 3
    return 0 if all(d["overall"] == "PASS" for d in docs) else 1


if __name__ == "__main__":
    sys.exit(main())
