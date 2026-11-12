"""Matrix entries (IMP-014).  Pure data + small helpers; no side effects on import."""
from __future__ import annotations

import os
from typing import Dict, List

from . import images

KERNEL_ARM64 = "linux-image-6.12.107+deb13-arm64"

# What the product's support table is EXPECTED to answer for each entry (independent of the code under
# test: derived from the roadmap/IMP-015 rules - mutex owner and heap-chunk decoding are LP64-glibc only,
# syscall names exist for aarch64).  Targets outside the supported scope (ARM32, musl) are refused by
# extractor/target_abi.py and are not part of the matrix.
_NS = "NOT_SUPPORTED_ON_TARGET"
_OK = "SUPPORTED"
EXPECTED_SUPPORT = {
    "aarch64-glibc": {"mutex_owner": _OK, "allocator_chunks": _OK, "syscall_names": _OK, "tcb_scan": _NS,
                      "frame_layout": _OK, "cfi_unwind": _OK},
}

ENTRIES: Dict[str, dict] = {
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
    return all(os.path.isfile(v) for v in p.values())


def prepare_entry(name: str) -> Dict[str, str]:
    """Download (checksum-verified) and build the guest images for ``name`` into the cache."""
    e = ENTRIES[name]
    return images.build_debian_entry(e["deb_arch"], e["kernel_pkg"], entry_cache(name))
