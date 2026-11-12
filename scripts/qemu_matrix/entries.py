"""Matrix entries (IMP-014).  Pure data + small helpers; no side effects on import."""
from __future__ import annotations

import os
from typing import Dict, List

from . import images

KERNEL_ARMMP = "linux-image-6.12.107+deb13-armmp"
KERNEL_ARM64 = "linux-image-6.12.107+deb13-arm64"

# What the product's support table is EXPECTED to answer for each entry (independent of the code under
# test: derived from the roadmap/IMP-015 rules - mutex owner and heap-chunk decoding are LP64-glibc only,
# arm 32-bit has no CFI unwinding / frame layout, syscall names exist for arm/aarch64).
_NS = "NOT_SUPPORTED_ON_TARGET"
_OK = "SUPPORTED"
EXPECTED_SUPPORT = {
    "arm32-glibc": {"mutex_owner": _NS, "allocator_chunks": _NS, "syscall_names": _OK, "tcb_scan": _NS,
                    "frame_layout": _NS, "cfi_unwind": _NS},
    "arm32-musl": {"mutex_owner": _NS, "allocator_chunks": _NS, "syscall_names": _OK, "tcb_scan": _NS,
                   "frame_layout": _NS, "cfi_unwind": _NS},
    "aarch64-glibc": {"mutex_owner": _OK, "allocator_chunks": _OK, "syscall_names": _OK, "tcb_scan": _NS,
                      "frame_layout": _OK, "cfi_unwind": _OK},
}

ENTRIES: Dict[str, dict] = {
    "arm32-glibc": {
        "name": "arm32-glibc",
        "title": "ARM32 + glibc (Debian trixie userland, BusyBox applets)",
        "qemu_bin": "qemu-system-arm", "machine": "virt,highmem=off", "cpu": "cortex-a15",
        "console_tty": "ttyAMA0", "mem_mb": 128,
        "userland": "debian", "deb_arch": "armhf", "kernel_pkg": KERNEL_ARMMP, "kernel_deb_arch": "armhf",
        "cc": "arm-linux-gnueabihf-gcc", "libc": "glibc",
        "uname_m": "armv7l", "collector_arch": "arm",
        "expected_abi": {"architecture": "arm", "word_size": 32, "endianness": "little", "libc": "glibc"},
        "expected_support": EXPECTED_SUPPORT["arm32-glibc"],
    },
    "arm32-musl": {
        "name": "arm32-musl",
        "title": "ARM32 + musl (Alpine v3.22 userland, BusyBox)",
        "qemu_bin": "qemu-system-arm", "machine": "virt,highmem=off", "cpu": "cortex-a15",
        "console_tty": "ttyAMA0", "mem_mb": 128,
        "userland": "alpine", "alpine_arch": "armv7", "kernel_pkg": KERNEL_ARMMP, "kernel_deb_arch": "armhf",
        "cc": "arm-linux-gnueabihf-gcc", "libc": "musl",
        "musl_loader": "/lib/ld-musl-armhf.so.1", "musl_libc_so": "libc.musl-armv7.so.1",
        "uname_m": "armv7l", "collector_arch": "arm",
        "expected_abi": {"architecture": "arm", "word_size": 32, "endianness": "little", "libc": "musl"},
        "expected_support": EXPECTED_SUPPORT["arm32-musl"],
    },
    "aarch64-glibc": {
        "name": "aarch64-glibc",
        "title": "aarch64 + glibc (Debian trixie userland, BusyBox applets)",
        "qemu_bin": "qemu-system-aarch64", "machine": "virt", "cpu": "cortex-a72",
        "console_tty": "ttyAMA0", "mem_mb": 128,
        "userland": "debian", "deb_arch": "arm64", "kernel_pkg": KERNEL_ARM64, "kernel_deb_arch": "arm64",
        "cc": "aarch64-linux-gnu-gcc", "libc": "glibc",
        "uname_m": "aarch64", "collector_arch": "aarch64",
        "expected_abi": {"architecture": "aarch64", "word_size": 64, "endianness": "little", "libc": "glibc"},
        "expected_support": EXPECTED_SUPPORT["aarch64-glibc"],
    },
}


def entry_names() -> List[str]:
    return list(ENTRIES)


def entry_cache(name: str) -> str:
    return os.path.join(images.cache_dir(), name)


def image_paths(name: str) -> Dict[str, str]:
    d = entry_cache(name)
    return {"kernel": os.path.join(d, "vmlinuz"), "initrd": os.path.join(d, "initramfs.cpio.gz")}


def images_ready(name: str) -> bool:
    """Pure existence check used by tests: never downloads or builds anything."""
    p = image_paths(name)
    ok = all(os.path.isfile(v) for v in p.values())
    if ENTRIES[name]["libc"] == "musl":
        ok = ok and os.path.isdir(os.path.join(entry_cache(name), "musl-sysroot", "usr", "include"))
    return ok


def prepare_entry(name: str) -> Dict[str, str]:
    """Download (checksum-verified) and build the guest images for ``name`` into the cache."""
    e = ENTRIES[name]
    out = entry_cache(name)
    if e["userland"] == "debian":
        res = images.build_debian_entry(e["deb_arch"], e["kernel_pkg"], out)
    else:
        res = images.build_alpine_entry(e["alpine_arch"], e["kernel_deb_arch"], e["kernel_pkg"], out)
        images.build_musl_sysroot(e["alpine_arch"], out)
    return res
