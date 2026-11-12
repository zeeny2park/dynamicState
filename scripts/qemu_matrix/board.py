"""Run the same checks against a REAL board over SSH (manual procedure: docs/EMBEDDED_BOARD_RUN.md).

    python3 -m scripts.qemu_matrix board --host 192.168.1.50 --user root --key ~/.ssh/id_board \
        --arch aarch64 --cc aarch64-linux-gnu-gcc --out board_record

Nothing is fabricated: the JSON written is exactly what the checks observed, plus the board facts the
operator passes in (--board-name etc.).  Needs the cross compiler for the board, `make -C target/collector dist`,
and SSH root (or same-user) access with permission to read /proc/<pid>/mem of the test targets.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
from typing import Any, Dict, List, Optional

from . import build_targets, checks, guest as guest_mod, results
from .entries import _NS, _OK

_ARCH = {"aarch64": (64, "little", "aarch64"), "x86_64": (64, "little", "x86_64")}
LIBC = "glibc"  # the only supported libc (musl / ARM32 targets are refused by extractor/target_abi.py)


def expected_support_for(arch: str) -> Dict[str, str]:
    return {
        "mutex_owner": _OK, "allocator_chunks": _OK, "syscall_names": _OK,
        "tcb_scan": _OK,  # x86_64 self-pointer scan and aarch64 dtv-validated discovery (glibc)
        "frame_layout": _OK, "cfi_unwind": _OK,
    }


def board_entry(arch: str, cc: str, name: str, uname_m: Optional[str] = None) -> Dict[str, Any]:
    word, endian, um = _ARCH[arch]
    return {
        "name": name, "title": f"real board {name} ({arch}, {LIBC})", "cc": cc, "libc": LIBC,
        "uname_m": uname_m or um, "collector_arch": arch, "mem_mb": 0,
        "expected_abi": {"architecture": arch, "word_size": word, "endianness": endian, "libc": LIBC},
        "expected_support": expected_support_for(arch),
    }


class BoardGuest(guest_mod.Guest):
    """A real machine reachable over SSH (no VM lifecycle)."""

    def __init__(self, host: str, port: int, user: str, key: str, workdir: str):
        self.host, self.user = host, user
        self.port = port
        self.key = key
        self.workdir = workdir
        self.vm = None
        self.boot_info: Dict[str, Any] = {}

    def start(self) -> None:
        rc, _, err = self.ssh("true", timeout=30)
        if rc != 0:
            raise RuntimeError(f"cannot ssh to {self.user}@{self.host}:{self.port}: {err.strip()}")
        self.ssh(f"mkdir -p {self.workdir}")

    def stop(self) -> Dict[str, Any]:
        self.ssh(f"pkill -f '{self.workdir}/(memtarget|deadlock)' 2>/dev/null; rm -f {self.workdir}/memtarget {self.workdir}/deadlock "
                 f"{self.workdir}/mem.out {self.workdir}/dl.out")
        return {"board": True}

    def ssh_base(self) -> List[str]:
        return ["ssh", "-p", str(self.port), "-i", self.key, "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
                *guest_mod.SSH_COMMON_OPTS, f"{self.user}@{self.host}"]

    def make_adapter(self, transport=None, **kw):
        from extractor.target_adapter import RemoteSshTargetAdapter
        tr = transport or guest_mod.CountingTransport()
        params = dict(host=self.host, user=self.user, port=self.port, key_file=self.key, timeout_sec=30.0,
                      command_runner=tr.runner, stream_opener=tr.opener)
        params.update(kw)
        return RemoteSshTargetAdapter(**params), tr


def run_board(args: argparse.Namespace) -> int:
    entry = board_entry(args.arch, args.cc, args.board_name, args.uname_m)
    doc = results.new_result(entry)
    doc["guest"] = {"board_name": args.board_name, "notes": args.notes}
    t0 = time.monotonic()
    g = BoardGuest(args.host, args.port, args.user, os.path.expanduser(args.key), args.workdir)
    try:
        outdir = os.path.join(args.out, "targets")
        targets = build_targets.build_entry_targets(entry, outdir)
        g.start()
        rc, un, _ = g.ssh("uname -a; cat /proc/cpuinfo | head -20; free; busybox 2>&1 | head -1; ls -l /lib/ld-* /lib/*/ld-* 2>/dev/null")
        doc["guest"]["facts"] = un.strip().splitlines()
        ctx = checks.Ctx(g, entry, targets, checks.host_reference())
        ctx.start_memtarget()
        out = doc["checks"]
        out.append(checks.guarded("C1_collector_deploy_and_slice", "deploy", lambda: checks.c1_deploy_and_slice(ctx)))
        out.append(checks.guarded("C1b_noexec_fallback_location", "noexec", lambda: checks.c1b_noexec_fallback(ctx)))
        out.append(checks.guarded("C6_process_discovery_and_identity", "discovery", lambda: checks.c6_discovery(ctx)))
        out.append(checks.guarded("C2a_daemon_channel", "daemon", lambda: checks.c2a_daemon_channel(ctx)))
        out.append(checks.guarded("C2b_no_collector_fallback", "fallback", lambda: checks.c2b_fallback(ctx)))
        out.append(checks.guarded("C3_abi_detection", "abi", lambda: checks.c3_abi(ctx)))
        ctx.start_deadlock()
        holder: Dict[str, Any] = {}

        def _dl():
            holder["run"] = checks.collect_deadlock(ctx)
            return checks.c4a_deadlock(ctx, holder["run"])
        out.append(checks.guarded("C4a_deadlock_diagnosis", "deadlock", _dl))
        if "run" in holder:
            out.append(checks.guarded("C4b_glibc_only_gating", "gating", lambda: checks.c4b_gating(ctx)))
            out.append(checks.guarded("C4c_futex_syscall_names", "syscall", lambda: checks.c4c_syscall_names(ctx)))
            out.append(checks.guarded("C4d_diagnose_entry_point", "diagnose", lambda: checks.c4d_diagnose_entry_point(ctx)))
            out.append(checks.guarded("C5_collection_cost", "cost", lambda: checks.c5_cost(ctx, holder["run"])))
    except SystemExit:
        raise
    except BaseException as exc:  # noqa: BLE001
        doc["infrastructure_error"] = f"{type(exc).__name__}: {exc}"
    finally:
        doc["teardown"] = g.stop()
        doc["duration_s"] = round(time.monotonic() - t0, 1)
        doc["overall"] = results.overall(doc["checks"], doc["infrastructure_error"])
        os.makedirs(args.out, exist_ok=True)
        path = os.path.join(args.out, f"{args.board_name}.json")
        with open(path, "w") as f:
            json.dump(doc, f, indent=1, default=str)
            f.write("\n")
    print(f"board result: {doc['overall']} -> {path}")
    for c in doc["checks"]:
        print(f"  {c['status']:24s} {c['id']}: {c['summary'][:150]}")
    return 0 if doc["overall"] == "PASS" else 1
