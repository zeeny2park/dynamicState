"""Reproducible guest-image construction for the QEMU matrix (IMP-014).

Nothing here runs implicitly: ``python3 -m scripts.qemu_matrix prepare`` calls the build functions.
Normal test runs only check existence (see ``matrix.images_ready``).

Guest = kernel + one initramfs (no disk image, no root needed):

* kernel: Debian trixie ``linux-image-*-arm64`` (virtio-pci built in; virtio_net as module)
* userland (glibc): Debian trixie debs (busybox-static, dropbear-bin, libc6 closure), resolved through the
  ``Release`` -> ``Packages.xz`` -> per-deb SHA256 chain (HTTPS; the Release GPG signature is not checked)
"""
from __future__ import annotations

import gzip
import hashlib
import json
import lzma
import os
import re
import shutil
import stat
import subprocess
import urllib.request
from typing import Dict, List, Optional, Tuple

DEBIAN_MIRROR = "https://deb.debian.org/debian"
DEBIAN_SUITE = "trixie"

MODULES = ["failover", "net_failover", "virtio_net"]


def cache_dir() -> str:
    return os.environ.get("DYNAMICSTATE_QEMU_CACHE") or os.path.join(
        os.path.expanduser("~"), ".cache", "dynamicstate-qemu")


# ---------------------------------------------------------------- downloads
def _manifest_path() -> str:
    return os.path.join(cache_dir(), "downloads.json")


def _load_manifest() -> Dict[str, dict]:
    try:
        with open(_manifest_path()) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def download(url: str, expect_sha256: Optional[str] = None, name: Optional[str] = None) -> str:
    """Download ``url`` into the cache (idempotent), verify ``expect_sha256`` when given, record it."""
    dl = os.path.join(cache_dir(), "dl")
    os.makedirs(dl, exist_ok=True)
    dest = os.path.join(dl, name or re.sub(r"[^A-Za-z0-9._+-]", "_", url.split("://", 1)[-1]))
    if not (os.path.isfile(dest) and (expect_sha256 is None or sha256_file(dest) == expect_sha256)):
        tmp = dest + ".part"
        req = urllib.request.Request(url, headers={"User-Agent": "dynamicstate-qemu-matrix"})
        with urllib.request.urlopen(req, timeout=120) as r, open(tmp, "wb") as f:
            shutil.copyfileobj(r, f)
        os.replace(tmp, dest)
    digest = sha256_file(dest)
    if expect_sha256 and digest != expect_sha256:
        os.unlink(dest)
        raise RuntimeError(f"sha256 mismatch for {url}: expected {expect_sha256}, got {digest}")
    man = _load_manifest()
    man[url] = {"url": url, "sha256": digest, "size": os.path.getsize(dest),
                "verified_against": "published checksum" if expect_sha256 else "none (recorded only)"}
    os.makedirs(cache_dir(), exist_ok=True)
    with open(_manifest_path(), "w") as f:
        json.dump(man, f, indent=1, sort_keys=True)
    return dest


def downloads_manifest() -> List[dict]:
    return sorted(_load_manifest().values(), key=lambda r: r["url"])


# ---------------------------------------------------------------- cpio (newc) writer
def _cpio_entry(name: str, mode: int, data: bytes = b"", rdev: Tuple[int, int] = (0, 0), ino: int = 0) -> bytes:
    nm = name.encode() + b"\0"
    hdr = "070701" + "".join("%08X" % v for v in (
        ino, mode, 0, 0, 1, 0, len(data), 0, 0, rdev[0], rdev[1], len(nm), 0))
    out = hdr.encode() + nm
    out += b"\0" * ((4 - len(out) % 4) % 4)
    out += data
    out += b"\0" * ((4 - len(data) % 4) % 4)
    return out


def cpio_from_tree(root: str, extra: Optional[List[Tuple[str, int, bytes, Tuple[int, int]]]] = None) -> bytes:
    """newc archive of ``root`` (uid/gid 0, mtime 0 -> reproducible) + ``extra`` (name, mode, data, rdev)."""
    out = bytearray()
    ino = 1
    for dp, dns, fns in os.walk(root):
        dns.sort()
        rel = os.path.relpath(dp, root)
        names = []
        for n in sorted(dns + fns):
            names.append(n if rel == "." else os.path.join(rel, n))
        if rel != ".":
            pass
        for rn in names:
            p = os.path.join(root, rn)
            st = os.lstat(p)
            ino += 1
            if stat.S_ISLNK(st.st_mode):
                out += _cpio_entry(rn, stat.S_IFLNK | 0o777, os.readlink(p).encode(), ino=ino)
            elif stat.S_ISDIR(st.st_mode):
                out += _cpio_entry(rn, stat.S_IFDIR | (st.st_mode & 0o7777), ino=ino)
            elif stat.S_ISREG(st.st_mode):
                with open(p, "rb") as f:
                    out += _cpio_entry(rn, stat.S_IFREG | (st.st_mode & 0o7777), f.read(), ino=ino)
    for name, mode, data, rdev in (extra or []):
        ino += 1
        out += _cpio_entry(name, mode, data, rdev, ino=ino)
    out += _cpio_entry("TRAILER!!!", 0)
    return bytes(out)


def key_overlay_cpio(pubkey: str) -> bytes:
    """Per-run initramfs fragment carrying root's authorized_keys (appended to the base image)."""
    out = bytearray()
    out += _cpio_entry("root", stat.S_IFDIR | 0o700, ino=900)
    out += _cpio_entry("root/.ssh", stat.S_IFDIR | 0o700, ino=901)
    out += _cpio_entry("root/.ssh/authorized_keys", stat.S_IFREG | 0o600, pubkey.encode(), ino=902)
    out += _cpio_entry("TRAILER!!!", 0)
    return bytes(out)


_TRAILER = _cpio_entry("TRAILER!!!", 0)


def compose_initrd(base_gz: str, pubkey: str, out_path: str) -> str:
    """Base initramfs + per-run authorized_keys as ONE gzip'd archive (base trailer stripped)."""
    with gzip.open(base_gz, "rb") as f:
        raw = f.read()
    if not raw.endswith(_TRAILER):
        raise RuntimeError("unexpected base initramfs layout (no trailing TRAILER!!! entry)")
    raw = raw[: -len(_TRAILER)] + key_overlay_cpio(pubkey)
    with open(out_path, "wb") as o, gzip.GzipFile(fileobj=o, mode="wb", compresslevel=1, mtime=0) as gz:
        gz.write(raw)
    return out_path


# ---------------------------------------------------------------- Debian
def _debian_packages(deb_arch: str) -> Dict[str, dict]:
    rel = download(f"{DEBIAN_MIRROR}/dists/{DEBIAN_SUITE}/Release", name=f"debian-{DEBIAN_SUITE}-Release")
    rel_txt = open(rel, errors="replace").read()
    sec = rel_txt.split("SHA256:", 1)[1]
    want = f"main/binary-{deb_arch}/Packages.xz"
    m = re.search(r"^ ([0-9a-f]{64})\s+\d+\s+" + re.escape(want) + r"$", sec, re.M)
    if not m:
        raise RuntimeError(f"{want} not listed in Release")
    pk = download(f"{DEBIAN_MIRROR}/dists/{DEBIAN_SUITE}/{want}", m.group(1),
                  name=f"debian-{DEBIAN_SUITE}-Packages-{deb_arch}.xz")
    txt = lzma.open(pk, "rt", errors="replace").read()
    pkgs: Dict[str, dict] = {}
    for stanza in txt.split("\n\n"):
        d: Dict[str, str] = {}
        key = None
        for line in stanza.splitlines():
            if line[:1] in " \t" and key:
                d[key] += "\n" + line
            elif ":" in line:
                key, v = line.split(":", 1)
                d[key] = v.strip()
        if "Package" in d:
            pkgs[d["Package"]] = d
    return pkgs


def _deb_closure(pkgs: Dict[str, dict], roots: List[str]) -> List[dict]:
    provides: Dict[str, str] = {}
    for n, d in pkgs.items():
        for p in d.get("Provides", "").split(","):
            p = re.sub(r"[ (].*", "", p.strip())
            if p:
                provides.setdefault(p, n)
    out: Dict[str, dict] = {}
    todo = list(roots)
    while todo:
        n = todo.pop()
        n = n if n in pkgs else provides.get(n, n)
        if n in out:
            continue
        if n not in pkgs:
            raise RuntimeError(f"debian package {n} not found")
        out[n] = pkgs[n]
        for fld in ("Pre-Depends", "Depends"):
            for dep in pkgs[n].get(fld, "").split(","):
                alt = dep.split("|")[0].strip()
                alt = re.sub(r"[ (:].*", "", alt)
                if alt:
                    todo.append(alt)
    return list(out.values())


def _merge_usr(root: str) -> None:
    """Make /lib /bin /sbin symlinks into /usr (merged-usr) after extracting debs into one tree."""
    for d in ("lib", "bin", "sbin", "lib64"):
        p = os.path.join(root, d)
        if os.path.islink(p):
            continue
        dst = os.path.join(root, "usr", d)
        if not os.path.isdir(p):
            if os.path.isdir(dst):
                os.symlink(os.path.join("usr", d), p)
            continue
        os.makedirs(dst, exist_ok=True)
        for dp, dns, fns in os.walk(p):
            rel = os.path.relpath(dp, p)
            os.makedirs(os.path.join(dst, rel), exist_ok=True)
            for fn in fns + [x for x in dns if os.path.islink(os.path.join(dp, x))]:
                src = os.path.join(dp, fn)
                tgt = os.path.join(dst, rel, fn)
                if os.path.lexists(tgt):
                    os.unlink(tgt)
                shutil.move(src, tgt)
        shutil.rmtree(p)
        os.symlink(os.path.join("usr", d), p)


INIT_SCRIPT = r"""#!/bin/busybox sh
/bin/busybox mkdir -p /proc /sys /dev /tmp /run /var/run
/bin/busybox mount -t proc proc /proc
/bin/busybox mount -t sysfs sys /sys
/bin/busybox mount -t devtmpfs dev /dev 2>/dev/null
/bin/busybox mkdir -p /dev/pts
/bin/busybox mount -t devpts devpts /dev/pts
/bin/busybox mount -t tmpfs tmpfs /tmp
[ -e /bin/ls ] || /bin/busybox --install -s /bin
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
for m in __MODULES__; do insmod /modules/$m.ko > /dev/console 2>&1; done
sleep 1
echo "net: $(ls /sys/class/net) mods: $(cat /proc/modules | cut -d' ' -f1 | tr '\n' ' ') pci: $(ls /sys/bus/pci/devices)" > /dev/console
ip link set lo up
ip link set eth0 up
ip addr add 10.0.2.15/24 dev eth0
ip route add default via 10.0.2.2
chmod 700 /root /root/.ssh; chmod 600 /root/.ssh/authorized_keys
echo "dynamicstate-matrix: starting dropbear" > /dev/console
mkdir -p /etc/dropbear
dropbearkey -t ed25519 -f /etc/dropbear/hk >/dev/console 2>&1
dropbear -r /etc/dropbear/hk -s -g -E -p 22 2>/run/dropbear.log
echo "dynamicstate-matrix: READY $(uname -m)" > /dev/console
exec /bin/busybox sh -c 'while :; do sleep 3600; done'
"""


def _write_common_etc(root: str) -> None:
    os.makedirs(os.path.join(root, "etc"), exist_ok=True)
    with open(os.path.join(root, "etc", "passwd"), "w") as f:
        f.write("root:x:0:0:root:/root:/bin/sh\n")
    with open(os.path.join(root, "etc", "group"), "w") as f:
        f.write("root:x:0:\n")
    with open(os.path.join(root, "etc", "shells"), "w") as f:
        f.write("/bin/sh\n/bin/ash\n")
    for d in ("root", "tmp", "proc", "sys", "dev", "run", "modules", "var/run"):
        os.makedirs(os.path.join(root, d), exist_ok=True)


def _extract_kernel(deb_arch: str, kernel_pkg: str, outdir: str) -> Tuple[str, str]:
    """Returns (kernel image path, modules dir containing decompressed *.ko)."""
    pkgs = _debian_packages(deb_arch)
    st = pkgs[kernel_pkg]
    deb = download(f"{DEBIAN_MIRROR}/{st['Filename']}", st["SHA256"])
    tmp = os.path.join(outdir, "kdeb")
    shutil.rmtree(tmp, ignore_errors=True)
    os.makedirs(tmp)
    subprocess.run(["dpkg-deb", "-x", deb, tmp], check=True)
    boot = os.path.join(tmp, "boot")
    vm = [f for f in os.listdir(boot) if f.startswith("vmlinuz-")][0]
    kernel = os.path.join(outdir, "vmlinuz")
    shutil.copy2(os.path.join(boot, vm), kernel)
    mods = os.path.join(outdir, "modules")
    shutil.rmtree(mods, ignore_errors=True)
    os.makedirs(mods)
    wanted = {m: None for m in MODULES}
    for dp, _, fns in os.walk(os.path.join(tmp, "usr", "lib", "modules")):
        for fn in fns:
            base = fn.split(".ko")[0]
            if base in wanted and ".ko" in fn:
                raw = open(os.path.join(dp, fn), "rb").read()
                if fn.endswith(".xz"):
                    raw = lzma.decompress(raw)
                elif fn.endswith(".gz"):
                    raw = gzip.decompress(raw)
                open(os.path.join(mods, base + ".ko"), "wb").write(raw)
                wanted[base] = True
    missing = [m for m, v in wanted.items() if not v]
    if missing:
        raise RuntimeError(f"kernel modules not found in {kernel_pkg}: {missing}")
    shutil.rmtree(tmp)
    return kernel, mods


def _finish_initramfs(root: str, mods: str, out_path: str) -> None:
    _write_common_etc(root)
    for m in MODULES:
        shutil.copy2(os.path.join(mods, m + ".ko"), os.path.join(root, "modules", m + ".ko"))
    p = os.path.join(root, "init")
    with open(p, "w") as f:
        f.write(INIT_SCRIPT.replace("__MODULES__", " ".join(MODULES)))
    os.chmod(p, 0o755)
    extra = [("dev/console", stat.S_IFCHR | 0o600, b"", (5, 1)), ("dev/null", stat.S_IFCHR | 0o666, b"", (1, 3))]
    blob = cpio_from_tree(root, extra)
    with open(out_path, "wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", compresslevel=9, mtime=0) as gz:
        gz.write(blob)


def build_debian_entry(deb_arch: str, kernel_pkg: str, outdir: str) -> Dict[str, str]:
    os.makedirs(outdir, exist_ok=True)
    kernel, mods = _extract_kernel(deb_arch, kernel_pkg, outdir)
    pkgs = _debian_packages(deb_arch)
    root = os.path.join(outdir, "rootfs")
    shutil.rmtree(root, ignore_errors=True)
    os.makedirs(root)
    used = [f"kernel:{kernel_pkg}={pkgs[kernel_pkg]['Version']}"]
    for st in _deb_closure(pkgs, ["busybox-static", "dropbear-bin", "libc6", "libgcc-s1"]):
        deb = download(f"{DEBIAN_MIRROR}/{st['Filename']}", st["SHA256"])
        subprocess.run(["dpkg-deb", "-x", deb, root], check=True)
        used.append(f"{st['Package']}={st['Version']}")
    _merge_usr(root)
    initrd = os.path.join(outdir, "initramfs.cpio.gz")
    _finish_initramfs(root, mods, initrd)
    shutil.rmtree(root)
    with open(os.path.join(outdir, "packages.txt"), "w") as f:
        f.write("\n".join(used) + "\n")
    return {"kernel": kernel, "initrd": initrd}
