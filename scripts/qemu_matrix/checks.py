"""The per-target checks of the matrix.  Each runs product code from the HOST against the guest over SSH."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import time
import traceback
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from . import build_targets
from .results import BLOCKED, FAIL, PASS, SKIPPED, check

KNOWN = b"DYNAMICSTATE-MATRIX-KNOWN-BUFFER-0123456789abcd\x00"
EXPECTED_LOCKS = {"g_mutex_a", "g_mutex_b"}
REPO = build_targets.REPO


def region_pattern(offset: int, size: int) -> bytes:
    """Content of the memtarget mmap region: byte i = (i*7+3) & 0xff."""
    return bytes(((offset + i) * 7 + 3) & 0xFF for i in range(size))


def parse_memtarget_line(text: str) -> Optional[Dict[str, int]]:
    m = re.search(r"pid=(\d+) known=0x([0-9a-f]+) len=(\d+) region=0x([0-9a-f]+) rlen=(\d+)", text)
    if not m:
        return None
    return {"pid": int(m.group(1)), "known": int(m.group(2), 16), "known_len": int(m.group(3)),
            "region": int(m.group(4), 16), "region_len": int(m.group(5))}


def unaligned_cases(region: int, known: int) -> List[Tuple[str, int, int, bytes]]:
    """(label, address, size, expected) - unaligned starts/ends, page-crossing and multi-page ranges."""
    return [
        ("known+1 len 40 (unaligned head)", known + 1, 40, KNOWN[1:41]),
        ("region+1 len 7", region + 1, 7, region_pattern(1, 7)),
        ("region+4093 len 10 (crosses page 0/1)", region + 4093, 10, region_pattern(4093, 10)),
        ("region+4095 len 2 (1 byte each side)", region + 4095, 2, region_pattern(4095, 2)),
        ("region+4097 len 4096 (unaligned, spans pages 1/2)", region + 4097, 4096, region_pattern(4097, 4096)),
        ("region+12283 len 5 (ends on region end)", region + 12283, 5, region_pattern(12283, 5)),
        ("region len 1 (single byte)", region, 1, region_pattern(0, 1)),
    ]


def count_procs(guest, comm_prefix: str) -> int:
    rc, out, _ = guest.ssh(
        "n=0; for p in /proc/[0-9]*; do read c < $p/comm 2>/dev/null || continue; "
        f"case \"$c\" in {comm_prefix}*) n=$((n+1));; esac; done; echo $n")
    try:
        return int(out.strip())
    except ValueError:
        return -1


class Ctx:
    """Shared state for one entry's checks."""

    def __init__(self, guest, entry: Dict[str, Any], targets: Dict[str, Dict[str, str]], host_ref: Dict[str, Any]):
        self.guest = guest
        self.entry = entry
        self.targets = targets
        self.host_ref = host_ref
        self.mem: Dict[str, int] = {}
        self.dl_pid: Optional[int] = None
        self.collector_info: Dict[str, Any] = {}
        self.abi = None

    def start_memtarget(self) -> Dict[str, int]:
        g = self.guest
        wd = g.workdir
        g.upload(self.targets["memtarget"]["guest"], f"{wd}/memtarget")
        g.ssh(f"sh -c '{wd}/memtarget > {wd}/mem.out 2>&1 &'")
        for _ in range(30):
            rc, out, _ = g.ssh(f"cat {wd}/mem.out")
            parsed = parse_memtarget_line(out)
            if parsed:
                self.mem = parsed
                return parsed
            time.sleep(1)
        raise RuntimeError("memtarget did not print its line")

    def start_deadlock(self) -> int:
        g = self.guest
        wd = g.workdir
        g.upload(self.targets["deadlock"]["guest"], f"{wd}/deadlock")
        g.ssh(f"sh -c '{wd}/deadlock > {wd}/dl.out 2>&1 &'")
        for _ in range(30):
            rc, out, _ = g.ssh(f"cat {wd}/dl.out")
            m = re.search(r"PID (\d+) started", out)
            if m:
                self.dl_pid = int(m.group(1))
                time.sleep(2.0)  # worker threads settle into the deadlock
                return self.dl_pid
            time.sleep(1)
        raise RuntimeError("deadlock fixture did not start")


def guarded(check_id: str, name: str, fn: Callable[[], Dict[str, Any]]) -> Dict[str, Any]:
    t0 = time.monotonic()
    try:
        res = fn()
    except Exception as exc:  # noqa: BLE001 - one failing check must not stop the matrix
        res = check(check_id, name, FAIL, f"check raised {type(exc).__name__}: {exc}",
                    {"traceback": traceback.format_exc(limit=6)})
    res.setdefault("duration_s", round(time.monotonic() - t0, 2))
    return res


# --------------------------------------------------------------------------------------- C1
def c1_deploy_and_slice(ctx: Ctx) -> Dict[str, Any]:
    cid, name = "C1_collector_deploy_and_slice", "collector deploys (right arch, static, version) and a slice read returns expected bytes"
    g, e = ctx.guest, ctx.entry
    ad, tr = g.make_adapter()
    try:
        dep = ad.ensure_remote_collector()
        ctx.collector_info = dep
        d: Dict[str, Any] = {"deploy": {k: v for k, v in dep.items() if k != "reason"}, "deploy_reason": dep.get("reason")}
        probs: List[str] = []
        if not dep.get("deployed"):
            return check(cid, name, FAIL, f"collector not deployed: {dep.get('status')} {dep.get('reason')}", d)
        rc, uname, _ = g.ssh("uname -m")
        d["guest_uname_m"] = uname.strip()
        if uname.strip() != e["uname_m"]:
            probs.append(f"guest uname -m {uname.strip()!r} != {e['uname_m']!r}")
        lb = dep.get("local_binary") or ""
        d["local_binary"] = os.path.relpath(lb, REPO) if lb else None
        if f"/dist/{e['collector_arch']}/" not in lb:
            probs.append(f"deployed binary is not dist/{e['collector_arch']}/ ({lb})")
        from extractor.target_abi import parse_elf_header
        hdr = parse_elf_header(open(lb, "rb").read(65536)) if lb else {}
        d["local_binary_elf"] = {k: hdr.get(k) for k in ("architecture", "word_size", "endianness", "interpreter")}
        if hdr.get("interpreter"):
            probs.append(f"collector binary is dynamically linked (PT_INTERP {hdr['interpreter']})")
        if hdr.get("architecture") != e["expected_abi"]["architecture"]:
            probs.append(f"collector ELF arch {hdr.get('architecture')}")
        path = dep["collector_path"]
        rc, vout, verr = g.ssh(f"{path} --version")
        d["remote_version_output"] = vout.strip()
        want = open(os.path.join(REPO, "target", "collector", "VERSION")).read().strip()
        d["expected_version"] = want
        if rc != 0 or want not in vout:
            probs.append(f"remote --version rc={rc} out={vout.strip()!r} (want {want})")
        ctx.start_memtarget() if not ctx.mem else None
        pid = ctx.mem["pid"]
        ad.pin_target_identity(pid)
        data, status, err = ad.read_memory(pid, ctx.mem["known"], len(KNOWN))
        d["slice_read"] = {"address": hex(ctx.mem["known"]), "size": len(KNOWN), "status": status, "error": err,
                           "bytes": data.decode("latin1") if data else None}
        d["daemon_stats_after_slice"] = dict(ad.daemon_stats)
        if status != "OBSERVED" or data != KNOWN:
            probs.append(f"slice read mismatch: status={status} got={data!r}")
        if ad.daemon_stats.get("requests", 0) < 1 and ad.daemon_stats.get("fallbacks", 0) >= 1:
            probs.append("slice read did not go through the collector")
        d["remote_commands"] = tr.snapshot()["commands"]
        if probs:
            return check(cid, name, FAIL, "; ".join(probs), d)
        return check(cid, name, PASS, f"{dep['status']} {dep.get('architecture')} collector v{dep.get('collector_version')}, "
                                      f"{dep.get('bytes_transferred')} bytes; slice of {len(KNOWN)} bytes at {hex(ctx.mem['known'])} matches", d,
                     remote_commands=tr.snapshot()["commands"])
    finally:
        ad.close()


# --------------------------------------------------------------------------------------- C1b
def c1b_noexec_fallback(ctx: Ctx) -> Dict[str, Any]:
    cid, name = "C1b_noexec_fallback_location", "deployment falls back to another location when the primary is mounted noexec"
    g = ctx.guest
    base = f"{g.workdir}/dsmx_noexec"
    fb = f"{g.workdir}/dsmx_fallback"
    rc, _, err = g.ssh(f"mkdir -p {base} {fb} && mount -t tmpfs -o noexec,size=2m tmpfs {base}")
    if rc != 0:
        return check(cid, name, SKIPPED, f"cannot create a noexec mount on the target (needs root + mount): {err.strip()[:120]}")
    ad, tr = g.make_adapter()
    try:
        rc, out, _ = g.ssh(f"cp /bin/true {base}/t 2>/dev/null; {base}/t; echo rc=$?")
        d: Dict[str, Any] = {"noexec_really_blocks_execution": "rc=0" not in out}
        dep = ad.ensure_remote_collector(remote_dest=f"{base}/dynamicstate-collector",
                                         fallback_dests=(f"{fb}/dynamicstate-collector",))
        d["deploy"] = {k: v for k, v in dep.items() if k != "reason"}
        d["reason"] = dep.get("reason")
        if not d["noexec_really_blocks_execution"]:
            return check(cid, name, SKIPPED, "mount -o noexec did not block execution on this target (cannot test the fallback)", d)
        if dep.get("deployed") and dep.get("collector_path", "").startswith(f"{fb}/"):
            data, status, _ = ad.read_memory(ctx.mem["pid"], ctx.mem["known"], len(KNOWN))
            d["read_via_fallback_copy"] = status
            if status == "OBSERVED" and data == KNOWN:
                return check(cid, name, PASS, f"noexec primary rejected, collector deployed to {dep['collector_path']} and used", d,
                             remote_commands=tr.snapshot()["commands"])
        return check(cid, name, FAIL, f"fallback deployment failed: {dep.get('status')} {dep.get('reason')}", d)
    finally:
        ad.close()
        g.ssh(f"umount {base} 2>/dev/null; rm -rf {base} {fb}")


# --------------------------------------------------------------------------------------- C6
def c6_discovery(ctx: Ctx) -> Dict[str, Any]:
    cid, name = "C6_process_discovery_and_identity", "process discovery / identity / maps through the target's BusyBox shell tools"
    g = ctx.guest
    pid, region = ctx.mem["pid"], ctx.mem["region"]
    ad, tr = g.make_adapter()
    try:
        probs = []
        found = ad.find_processes("memtarget")
        hit = [p for p in found if p["pid"] == pid]
        d: Dict[str, Any] = {"find_processes": [{k: p.get(k) for k in ("pid", "name", "executable")} for p in found[:4]]}
        if not hit or not hit[0].get("executable", "").endswith("/memtarget"):
            probs.append(f"find_processes('memtarget') did not return pid {pid} with its executable: {d['find_processes']}")
        ident = ad.get_process_identity(pid)
        d["identity"] = {k: ident.get(k) for k in ("architecture", "elf_type", "build_id", "start_time", "executable")}
        if ident.get("architecture") != ctx.entry["expected_abi"]["architecture"]:
            probs.append(f"identity architecture {ident.get('architecture')!r}")
        if not ident.get("build_id") or not ident.get("start_time") or not ident.get("boot_id"):
            probs.append("identity lacks build_id/start_time/boot_id")
        maps = ad.get_proc_maps(pid)
        reg = [m for m in maps if m["start_int"] <= region < m["end_int"]]
        d["maps"] = {"entries": len(maps), "region_mapping": reg[0]["permissions"] if reg else None}
        if not reg or reg[0]["permissions"][:2] != "rw":
            probs.append("anonymous rw region not found in /proc/PID/maps")
        st = ad.get_process_status(pid)
        d["status_fields"] = sorted(st)[:6]
        if "VmRSS" not in st:
            probs.append("VmRSS missing from status")
        live, _ = ad.check_liveness(pid)
        if not live:
            probs.append("check_liveness false for a live pid")
        if probs:
            return check(cid, name, FAIL, "; ".join(probs), d, remote_commands=tr.snapshot()["commands"])
        return check(cid, name, PASS, f"found pid {pid}, build-id {ident['build_id'][:12]}, {len(maps)} maps entries, rw region located", d,
                     remote_commands=tr.snapshot()["commands"])
    finally:
        ad.close()


# --------------------------------------------------------------------------------------- C2a
def c2a_daemon_channel(ctx: Ctx, n_reads: int = 30) -> Dict[str, Any]:
    cid, name = "C2a_daemon_channel", "daemon channel: N reads over one collector process"
    g = ctx.guest
    pid, region = ctx.mem["pid"], ctx.mem["region"]
    ad, tr = g.make_adapter(collector_path=ctx.collector_info.get("collector_path"))
    try:
        before = count_procs(g, "dynamicstate-co")
        bad = []
        t0 = time.monotonic()
        for i in range(n_reads):
            off = (i * 389) % (12288 - 64)
            data, status, err = ad.read_memory(pid, region + off, 64)
            if status != "OBSERVED" or data != region_pattern(off, 64):
                bad.append({"i": i, "off": off, "status": status, "err": err})
        wall = time.monotonic() - t0
        during = count_procs(g, "dynamicstate-co")
        stats = dict(ad.daemon_stats)
        snap = tr.snapshot()
        ad.close()
        time.sleep(1.0)
        after = count_procs(g, "dynamicstate-co")
        d = {"reads": n_reads, "bad_reads": bad, "wall_s": round(wall, 2), "daemon_stats": stats,
             "collector_processes_before": before, "collector_processes_during": during,
             "collector_processes_after_close": after, "ssh_commands": snap}
        probs = []
        if bad:
            probs.append(f"{len(bad)} reads wrong")
        if during != 1:
            probs.append(f"{during} collector processes on the target while the channel was open (want exactly 1)")
        if stats.get("opens") != 1 or stats.get("requests", 0) < n_reads or stats.get("fallbacks", 0):
            probs.append(f"daemon_stats unexpected: {stats}")
        if after != 0:
            probs.append(f"{after} collector process(es) left after close()")
        if probs:
            return check(cid, name, FAIL, "; ".join(probs), d, remote_commands=snap["commands"])
        return check(cid, name, PASS, f"{n_reads} reads, 1 collector process, 1 ssh channel, 0 left after close", d,
                     remote_commands=snap["commands"])
    finally:
        ad.close()


# --------------------------------------------------------------------------------------- C2b
def c2b_fallback(ctx: Ctx) -> Dict[str, Any]:
    cid, name = "C2b_no_collector_fallback", "no-collector fallback (guest BusyBox dd/tail/head) on unaligned ranges"
    g = ctx.guest
    pid = ctx.mem["pid"]
    cases = unaligned_cases(ctx.mem["region"], ctx.mem["known"])
    rc, ddv, _ = g.ssh("dd --help 2>&1 | head -1; tail --help 2>&1 | head -1; head --help 2>&1 | head -1; readlink /bin/dd /bin/tail /bin/head")
    ad, tr = g.make_adapter(collector_path=None, use_daemon=False)
    try:
        single = []
        probs = []
        for label, addr, size, want in cases:
            data, status, err = ad.read_memory(pid, addr, size)
            ok = (status == "OBSERVED" and data == want)
            single.append({"case": label, "ok": ok, "status": status, "got_len": len(data) if data else 0, "err": err})
            if not ok:
                probs.append(f"single read '{label}': status={status} len={len(data) if data else 0}")
        batch = ad.read_memory_batch(pid, [(a, s) for _, a, s, _ in cases])
        batch_ok = [r[1] == "OBSERVED" and r[0] == c[3] for r, c in zip(batch, cases)]
        if not all(batch_ok):
            probs.append(f"batch read mismatches at indexes {[i for i, v in enumerate(batch_ok) if not v]}")
        # unmapped address must be reported, not fabricated
        bad_data, bad_status, _ = ad.read_memory(pid, 0x10, 16)
        if bad_data:
            probs.append(f"unmapped read returned data ({bad_status})")
        snap = tr.snapshot()
        d = {"applets": ddv.strip().splitlines(), "single": single, "batch_ok": batch_ok,
             "unmapped_read_status": bad_status, "ssh_commands": snap}
        if probs:
            return check(cid, name, FAIL, "; ".join(probs), d, remote_commands=snap["commands"])
        return check(cid, name, PASS, f"{len(cases)} unaligned/page-crossing ranges correct singly and as one batch; unmapped read -> {bad_status}", d,
                     remote_commands=snap["commands"])
    finally:
        ad.close()


# --------------------------------------------------------------------------------------- C3
def c3_abi(ctx: Ctx) -> Dict[str, Any]:
    cid, name = "C3_abi_detection", "ABI detection through the remote adapter (arch, word size, endianness, libc, support table)"
    from extractor.target_abi import abi_support_summary, detect_target_abi
    g, e = ctx.guest, ctx.entry
    ad, tr = g.make_adapter()
    try:
        abi = detect_target_abi(ad, ctx.mem["pid"])
        ctx.abi = abi
        got = {k: getattr(abi, k) for k in ("architecture", "word_size", "endianness", "libc")}
        want = e["expected_abi"]
        sup = abi_support_summary(abi)
        got_sup = {f: v["status"] for f, v in sup.items()}
        d = {"detected": abi.to_dict(), "expected": want, "support": got_sup,
             "expected_support": e["expected_support"]}
        probs = []
        if abi.status != "DETECTED" or got != want:
            probs.append(f"ABI {got} != expected {want}")
        for f, exp in e["expected_support"].items():
            if got_sup.get(f) != exp:
                probs.append(f"support[{f}]={got_sup.get(f)} expected {exp}")
        if probs:
            return check(cid, name, FAIL, "; ".join(probs), d, remote_commands=tr.snapshot()["commands"])
        return check(cid, name, PASS, f"{got['architecture']}/{got['word_size']}-bit/{got['endianness']}-endian/{got['libc']}; "
                                      f"support table as expected", d, remote_commands=tr.snapshot()["commands"])
    finally:
        ad.close()


# --------------------------------------------------------------------------------------- host reference
def host_reference() -> Dict[str, Any]:
    """Run the same deadlock fixture natively on the host and diagnose it with the local adapter."""
    cc = shutil.which("gcc") or shutil.which("cc")
    if not cc:
        return {"available": False, "reason": "no host compiler", "locks": sorted(EXPECTED_LOCKS)}
    from extractor.diagnostic_recipes import RECIPE_POTENTIAL_DEADLOCK_PATTERNS, DiagnosticRecipeRegistry
    from extractor.runtime_evidence_provider import RuntimeEvidenceProvider
    tmp = tempfile.mkdtemp(prefix="dsqemu_hostref_")
    proc = None
    try:
        out = os.path.join(tmp, "deadlock")
        subprocess.run(build_targets.cc_cmd(cc, build_targets.TARGET_SRC["deadlock"], out), check=True,
                       capture_output=True)
        proc = subprocess.Popen([out], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.5)
        prov = RuntimeEvidenceProvider()
        recipe = DiagnosticRecipeRegistry.get_recipe(RECIPE_POTENTIAL_DEADLOCK_PATTERNS)
        deadline = time.monotonic() + 8
        epoch, obs = 1, {}
        while True:
            obs, _ = prov.collect_for_recipe(recipe, proc.pid, out, session_id=f"hostref_{proc.pid}", epoch_id=epoch)
            if obs.get("deadlock_detected") or time.monotonic() > deadline:
                break
            epoch += 1
            time.sleep(0.2)
        res = DiagnosticRecipeRegistry.evaluate_recipe(RECIPE_POTENTIAL_DEADLOCK_PATTERNS, obs)
        return {"available": True, "deadlock_detected": bool(obs.get("deadlock_detected")),
                "locks": sorted({e["lock_name"] for e in obs.get("deadlock_cycle", [])}),
                "recipe_status": res.status, "host_arch": os.uname().machine}
    finally:
        if proc is not None:
            proc.kill()
            proc.wait()
        shutil.rmtree(tmp, ignore_errors=True)


# --------------------------------------------------------------------------------------- C4
def collect_deadlock(ctx: Ctx, attempts: int = 3) -> Dict[str, Any]:
    """Run the production deadlock path against the guest; shared by C4a/C4d/C5."""
    from extractor.diagnostic_recipes import RECIPE_POTENTIAL_DEADLOCK_PATTERNS, DiagnosticRecipeRegistry
    from extractor.runtime_evidence_provider import RuntimeEvidenceProvider
    g, e = ctx.guest, ctx.entry
    ad, tr = g.make_adapter(collector_path=ctx.collector_info.get("collector_path"))
    try:
        ad.pin_target_identity(ctx.dl_pid)
        prov = RuntimeEvidenceProvider(adapter=ad)
        recipe = DiagnosticRecipeRegistry.get_recipe(RECIPE_POTENTIAL_DEADLOCK_PATTERNS)
        tr.commands = 0
        t0 = time.monotonic()
        obs: Dict[str, Any] = {}
        n = 0
        for n in range(1, attempts + 1):
            obs, _ = prov.collect_for_recipe(recipe, ctx.dl_pid, ctx.targets["deadlock"]["debug"],
                                             session_id=f"qemu_{e['name']}_{ctx.dl_pid}", epoch_id=n)
            if obs.get("deadlock_detected") and obs.get("is_persistent"):
                break
        wall = time.monotonic() - t0
        res = DiagnosticRecipeRegistry.evaluate_recipe(RECIPE_POTENTIAL_DEADLOCK_PATTERNS, obs)
        ci = obs.get("callstacks_info") or {}
        return {"obs": obs, "recipe_status": res.status, "recipe_basis": res.confidence_basis,
                "recipe_details": dict(res.details), "wall_s": round(wall, 2), "ssh_commands": tr.snapshot()["commands"],
                "collections": n, "callstacks_status": ci.get("status"), "lock_owner_status": ci.get("lock_owner_status"),
                "lock_owner_reason": ci.get("lock_owner_status_reason"), "cfi_status": ci.get("cfi_unwind_status"),
                "threads": obs.get("threads") or []}
    finally:
        ad.close()


def c4a_deadlock(ctx: Ctx, run: Dict[str, Any]) -> Dict[str, Any]:
    cid, name = "C4a_deadlock_diagnosis", "deadlock diagnosis of proc_thread_circular_deadlock (vs. host result)"
    obs = run["obs"]
    ref = ctx.host_ref
    locks = sorted({c["lock_name"] for c in obs.get("deadlock_cycle", [])})
    d = {"host_reference": ref, "remote": {"deadlock_detected": bool(obs.get("deadlock_detected")), "locks": locks,
                                           "recipe_status": run["recipe_status"], "lock_owner_status": run["lock_owner_status"],
                                           "collections": run["collections"], "wall_s": run["wall_s"],
                                           "ssh_commands": run["ssh_commands"]}}
    want_locks = ref.get("locks") if ref.get("available") else sorted(EXPECTED_LOCKS)
    if obs.get("deadlock_detected") and locks == want_locks and run["recipe_status"] == ref.get("recipe_status", "SUPPORTED"):
        limits = []
        if all(t.get("syscall") is None and t.get("syscall_nr") is None for t in run["threads"]):
            limits.append("remote get_threads carries no syscall fields; waiters were found via stack scan")
        d["limitations"] = limits
        return check(cid, name, PASS, f"verdict {run['recipe_status']} = host; cycle locks {locks} = host", d,
                     duration_s=run["wall_s"], remote_commands=run["ssh_commands"])
    if all(t.get("syscall") is None for t in run["threads"]):
        return check(cid, name, BLOCKED, "deadlock not established remotely and remote get_threads returns no syscall/wait info "
                                         "(thread-info collector command not available yet)", d,
                     duration_s=run["wall_s"], remote_commands=run["ssh_commands"])
    return check(cid, name, FAIL, f"remote deadlock_detected={obs.get('deadlock_detected')} locks={locks} "
                                  f"recipe={run['recipe_status']} vs host {ref}", d,
                 duration_s=run["wall_s"], remote_commands=run["ssh_commands"])


def c4b_gating(ctx: Ctx) -> Dict[str, Any]:
    cid, name = "C4b_glibc_only_gating", "remote heap walking (glibc allocator)"
    from extractor.heap_walker import STATUS_OK, STATUS_PARTIAL, HeapWalker
    g = ctx.guest
    ad, tr = g.make_adapter(collector_path=ctx.collector_info.get("collector_path"))
    try:
        t0 = time.monotonic()
        w = HeapWalker(ad, ctx.mem["pid"], abi=ctx.abi).walk()
        wall = time.monotonic() - t0
        n_chunks = len(w.chunks)
        d = {"heap_walk_status": w.status, "heap_walk_message": w.message, "chunks": n_chunks,
             "arenas": len(w.arenas), "wall_s": round(wall, 2), "ssh_commands": tr.snapshot()["commands"]}
        if w.status in (STATUS_OK, STATUS_PARTIAL):
            return check(cid, name, PASS, f"heap walk {w.status}: {n_chunks} chunks in {len(w.arenas)} arena(s)", d)
        if w.status == "INCONCLUSIVE_ABI_UNDETECTED" and "glibc version" in w.message:
            return check(cid, name, BLOCKED,
                         "heap walking is declared supported here but HeapWalker cannot identify the glibc version of a REMOTE target "
                         "(version probe is local-only / banner read from target memory failed) and answers INCONCLUSIVE - honest, "
                         "but the remote heap walk cannot run: " + w.message, d)
        return check(cid, name, FAIL, f"heap walk on a supported target returned {w.status}: {w.message}", d)
    finally:
        ad.close()


def c4c_syscall_names(ctx: Ctx) -> Dict[str, Any]:
    cid, name = "C4c_futex_syscall_names", "futex-waiting threads reported with the right syscall name"
    from extractor.target_abi import syscall_name
    g = ctx.guest
    pid = ctx.dl_pid
    rc, out, _ = g.ssh(f"for t in /proc/{pid}/task/*; do echo $(basename $t) $(cat $t/syscall); done")
    truth = {}
    for line in out.splitlines():
        p = line.split()
        if len(p) >= 2 and p[0].isdigit() and p[1].lstrip("-").isdigit():
            truth[int(p[0])] = int(p[1])
    futex_tids = [t for t, nr in truth.items() if (syscall_name(ctx.abi, nr) or "").startswith("futex")]
    d = {"guest_raw_syscalls": truth, "futex_waiters_by_abi_table": futex_tids,
         "table_names": {t: syscall_name(ctx.abi, nr) for t, nr in truth.items()}}
    if len(futex_tids) < 2:
        return check(cid, name, FAIL, f"ABI syscall table does not map the guest's raw syscall numbers {truth} to futex", d)
    ad, tr = g.make_adapter(collector_path=ctx.collector_info.get("collector_path"))
    try:
        threads = ad.get_threads(pid)
    finally:
        ad.close()
    by_tid = {t["tid"]: t for t in threads}
    d["remote_get_threads_fields"] = sorted({k for t in threads for k in t})
    missing = [t for t in futex_tids if by_tid.get(t, {}).get("syscall") is None and by_tid.get(t, {}).get("syscall_nr") is None]
    if missing:
        return check(cid, name, BLOCKED,
                     "RemoteSshTargetAdapter.get_threads returns no syscall/wchan fields (only tid/name/state); the table maps the guest's "
                     f"raw numbers {sorted(set(truth[t] for t in futex_tids))} to futex, but the product path cannot report them until the "
                     "collector thread-info command lands", d)
    def _reported_name(t):
        # The remote adapter reports the raw syscall record ({"state","nr","args","sp","pc"}), like the local
        # adapter; the name is derived from the number through the TARGET's ABI table, never the host's.
        sc = by_tid[t].get("syscall")
        if isinstance(sc, dict):
            nr = sc.get("nr")
            return syscall_name(ctx.abi, nr) if isinstance(nr, int) else None
        return str(sc) if sc is not None else None

    reported = {t: _reported_name(t) for t in futex_tids}
    d["reported_syscalls"] = {t: by_tid[t].get("syscall") for t in futex_tids}
    wrong = {t: by_tid[t].get("syscall") for t in futex_tids if "futex" not in str(reported[t])}
    not_blocked = [t for t in futex_tids
                   if isinstance(by_tid[t].get("syscall"), dict) and by_tid[t]["syscall"].get("state") != "blocked"]
    if wrong or not_blocked:
        return check(cid, name, FAIL, f"futex waiters reported with wrong syscall: {wrong or not_blocked}", d)
    return check(cid, name, PASS, f"threads {futex_tids} reported as futex (blocked, with sp/pc)", d)


# --------------------------------------------------------------------------------------- C5
def c5_cost(ctx: Ctx, deadlock_run: Dict[str, Any], n_reads: int = 100, n_pinned: int = 20) -> Dict[str, Any]:
    cid, name = "C5_collection_cost", "collection cost on the constrained guest (wall time, number of remote commands)"
    g = ctx.guest
    pid, region = ctx.mem["pid"], ctx.mem["region"]
    cpath = ctx.collector_info.get("collector_path")

    def run_reads(label: str, count: int, pin: bool, **kw) -> Dict[str, Any]:
        ad, tr = g.make_adapter(**kw)
        try:
            if pin:
                ad.pin_target_identity(pid)
            tr.commands = 0
            bad = 0
            t0 = time.monotonic()
            for i in range(count):
                off = (i * 211) % (12288 - 64)
                data, status, _ = ad.read_memory(pid, region + off, 64)
                if data != region_pattern(off, 64):
                    bad += 1
            wall = time.monotonic() - t0
            return {"mode": label, "reads": count, "wall_s": round(wall, 2), "ssh_commands": tr.snapshot()["commands"],
                    "per_read_ms": round(1000 * wall / count, 1), "wrong_reads": bad}
        finally:
            ad.close()

    rows = [
        run_reads("daemon channel (collector)", n_reads, False, collector_path=cpath, use_daemon=True),
        run_reads("one collector process per call", n_reads, False, collector_path=cpath, use_daemon=False),
        run_reads("no collector (busybox dd block pipeline)", n_reads, False, collector_path=None, use_daemon=False),
        run_reads("daemon channel + pinned identity", n_pinned, True, collector_path=cpath, use_daemon=True),
    ]
    d = {"read_modes": rows,
         "deadlock_diagnosis": {"wall_s": deadlock_run["wall_s"], "ssh_commands": deadlock_run["ssh_commands"],
                                "collections": deadlock_run["collections"]},
         "guest": {"vcpus": 1, "mem_mb": ctx.entry["mem_mb"], "accel": "tcg (software emulation; absolute times are pessimistic)"}}
    wrong = sum(r["wrong_reads"] for r in rows)
    if wrong:
        return check(cid, name, FAIL, f"{wrong} wrong reads while measuring", d)
    return check(cid, name, PASS,
                 f"deadlock {deadlock_run['wall_s']}s/{deadlock_run['ssh_commands']} cmds; 100 reads: " +
                 ", ".join(f"{r['mode'].split(' (')[0]} {r['wall_s']}s/{r['ssh_commands']} cmds" for r in rows[:3]), d,
                 duration_s=sum(r["wall_s"] for r in rows) + deadlock_run["wall_s"])
