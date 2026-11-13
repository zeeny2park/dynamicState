"""Target ABI detection and the supported-combination table (IMP-015).

The diagnosis code decodes target memory with layouts that are only valid for specific
(architecture, word size, endianness, libc) combinations: the glibc ``pthread_mutex_t`` owner
field, the ptmalloc chunk header, syscall numbers, the x86-64 TCB self-pointer invariant and
the x86-64 call/frame conventions.  This module

1. detects the ABI of the *target* process (never the host running the tool) through the
   target adapter abstraction (local or remote): ELF header of ``/proc/PID/exe``, the
   ``PT_INTERP`` interpreter path and the libc file mapped in ``/proc/PID/maps``;
2. holds ONE table of supported combinations per feature (:data:`SUPPORT_TABLE`);
3. answers ``check_support(abi, feature)`` with an explicit decision:
   ``SUPPORTED`` / ``NOT_SUPPORTED_ON_TARGET`` / ``INCONCLUSIVE_ABI_UNDETECTED``.

A feature that is not SUPPORTED must not return a value: callers report the decision instead.
When detection itself fails the answer is INCONCLUSIVE - never a guess and never the host ABI.
"""

import re
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# --------------------------------------------------------------------------------------
# Decision statuses
# --------------------------------------------------------------------------------------
SUPPORT_SUPPORTED = "SUPPORTED"
SUPPORT_NOT_SUPPORTED_ON_TARGET = "NOT_SUPPORTED_ON_TARGET"
SUPPORT_INCONCLUSIVE = "INCONCLUSIVE_ABI_UNDETECTED"

DETECTION_DETECTED = "DETECTED"
DETECTION_FAILED = "FAILED"

LIBC_GLIBC = "glibc"
LIBC_MUSL = "musl"
LIBC_UNKNOWN = "unknown"

# Features gated by the support table.
FEATURE_MUTEX_OWNER = "mutex_owner"
FEATURE_ALLOCATOR_CHUNKS = "allocator_chunks"
FEATURE_SYSCALL_NAMES = "syscall_names"
FEATURE_TCB_SCAN = "tcb_scan"
FEATURE_FRAME_LAYOUT = "frame_layout"
FEATURE_CFI_UNWIND = "cfi_unwind"

_ANY = None  # wildcard in the support table

# feature -> list of (architecture, libc, word_size_bits, endianness); None is a wildcard.
# Only combinations that have been exercised are listed; everything else is refused.
SUPPORT_TABLE: Dict[str, List[Tuple[Optional[str], Optional[str], Optional[int], Optional[str]]]] = {
    # glibc NPTL pthread_mutex_t: {int __lock; uint __count; int __owner; ...} on LP64.
    FEATURE_MUTEX_OWNER: [
        ("x86_64", LIBC_GLIBC, 64, "little"),
        ("aarch64", LIBC_GLIBC, 64, "little"),
    ],
    # ptmalloc chunk header (prev_size, size|flags; SIZE_SZ == 8) on LP64 glibc.
    FEATURE_ALLOCATOR_CHUNKS: [
        ("x86_64", LIBC_GLIBC, 64, "little"),
        ("aarch64", LIBC_GLIBC, 64, "little"),
    ],
    # Syscall numbers are a kernel ABI: independent of libc, but specific to the architecture.
    FEATURE_SYSCALL_NAMES: [
        ("x86_64", _ANY, 64, "little"),
        ("aarch64", _ANY, 64, _ANY),
        ("arm", _ANY, 32, _ANY),
    ],
    # x86_64: glibc tcbhead_t self-pointer invariant + struct pthread tid offsets.
    # aarch64: TLS variant I; thread pointer found from the thread's TID + dtv consistency at the top of its
    # stack / initial-TLS mapping (no hard-coded struct pthread layout; see
    # tests/test_aarch64_tcb_discovery.py).
    FEATURE_TCB_SCAN: [
        ("x86_64", LIBC_GLIBC, 64, "little"),
        ("aarch64", LIBC_GLIBC, 64, "little"),
    ],
    # IMP-011: frame parameter/local decoding.  The CFA of each frame comes from the CFI unwinder
    # (extractor/cfi_unwinder.py: .eh_frame/.debug_frame CFA programs, per-architecture DWARF register
    # numbering, call-site decoding) and DW_OP_fbreg is evaluated against DW_AT_frame_base
    # (DW_OP_call_frame_cfa or a register).  Exercised on aarch64 (executed) and x86_64.
    FEATURE_FRAME_LAYOUT: [
        ("x86_64", _ANY, 64, "little"),
        ("aarch64", _ANY, 64, "little"),
    ],
    # IMP-011: CFI call-stack unwinding from the kernel-reported SP/PC of a blocked thread.
    # 32-bit arm (EHABI .ARM.exidx, r11/r7 frame pointers, Thumb bit) is not implemented.
    FEATURE_CFI_UNWIND: [
        ("x86_64", _ANY, 64, "little"),
        ("aarch64", _ANY, 64, "little"),
    ],
}

# --------------------------------------------------------------------------------------
# Syscall name tables (blocking calls the thread diagnosis cares about + common ones).
# Numbers generated from the kernel uapi headers of each architecture.
# --------------------------------------------------------------------------------------
SYSCALL_NAMES_X86_64: Dict[int, str] = {
    0: "read", 1: "write", 3: "close", 7: "poll", 9: "mmap", 16: "ioctl", 17: "pread64",
    18: "pwrite64", 19: "readv", 20: "writev", 23: "select", 24: "sched_yield", 34: "pause",
    35: "nanosleep", 42: "connect", 43: "accept", 44: "sendto", 45: "recvfrom", 46: "sendmsg",
    47: "recvmsg", 60: "exit", 61: "wait4", 62: "kill", 65: "semop", 69: "msgsnd", 70: "msgrcv",
    73: "flock", 74: "fsync", 128: "rt_sigtimedwait", 130: "rt_sigsuspend", 202: "futex",
    208: "io_getevents", 220: "semtimedop", 230: "clock_nanosleep", 231: "exit_group",
    232: "epoll_wait", 234: "tgkill", 243: "mq_timedreceive", 247: "waitid", 257: "openat",
    270: "pselect6", 271: "ppoll", 281: "epoll_pwait", 288: "accept4", 299: "recvmmsg",
    307: "sendmmsg", 426: "io_uring_enter", 441: "epoll_pwait2", 449: "futex_waitv",
}

SYSCALL_NAMES_AARCH64: Dict[int, str] = {
    4: "io_getevents", 22: "epoll_pwait", 29: "ioctl", 32: "flock", 56: "openat", 57: "close",
    63: "read", 64: "write", 65: "readv", 66: "writev", 67: "pread64", 68: "pwrite64",
    72: "pselect6", 73: "ppoll", 82: "fsync", 93: "exit", 94: "exit_group", 95: "waitid",
    98: "futex", 101: "nanosleep", 115: "clock_nanosleep", 124: "sched_yield", 129: "kill",
    131: "tgkill", 133: "rt_sigsuspend", 137: "rt_sigtimedwait", 183: "mq_timedreceive",
    188: "msgrcv", 189: "msgsnd", 192: "semtimedop", 193: "semop", 202: "accept", 203: "connect",
    206: "sendto", 207: "recvfrom", 211: "sendmsg", 212: "recvmsg", 222: "mmap", 242: "accept4",
    243: "recvmmsg", 260: "wait4", 269: "sendmmsg", 426: "io_uring_enter", 441: "epoll_pwait2",
    449: "futex_waitv",
}

# ARM EABI (32-bit).  Includes the *_time64 variants used by 64-bit-time_t libcs.
SYSCALL_NAMES_ARM: Dict[int, str] = {
    1: "exit", 3: "read", 4: "write", 6: "close", 29: "pause", 37: "kill", 54: "ioctl",
    114: "wait4", 118: "fsync", 142: "_newselect", 143: "flock", 145: "readv", 146: "writev",
    158: "sched_yield", 162: "nanosleep", 168: "poll", 177: "rt_sigtimedwait",
    179: "rt_sigsuspend", 180: "pread64", 181: "pwrite64", 192: "mmap2", 240: "futex",
    245: "io_getevents", 248: "exit_group", 252: "epoll_wait", 265: "clock_nanosleep",
    268: "tgkill", 277: "mq_timedreceive", 280: "waitid", 283: "connect", 285: "accept",
    290: "sendto", 292: "recvfrom", 296: "sendmsg", 297: "recvmsg", 298: "semop",
    301: "msgsnd", 302: "msgrcv", 312: "semtimedop", 322: "openat", 335: "pselect6",
    336: "ppoll", 346: "epoll_pwait", 365: "recvmmsg", 366: "accept4", 374: "sendmmsg",
    407: "clock_nanosleep_time64", 413: "pselect6_time64", 414: "ppoll_time64",
    422: "futex_time64", 426: "io_uring_enter", 441: "epoll_pwait2", 449: "futex_waitv",
}

SYSCALL_TABLES: Dict[str, Dict[int, str]] = {
    "x86_64": SYSCALL_NAMES_X86_64,
    "aarch64": SYSCALL_NAMES_AARCH64,
    "arm": SYSCALL_NAMES_ARM,
}

# --------------------------------------------------------------------------------------
# ABI record
# --------------------------------------------------------------------------------------
_E_MACHINE = {
    3: "x86", 8: "mips", 20: "ppc", 21: "ppc64", 40: "arm", 62: "x86_64", 183: "aarch64",
}


@dataclass
class TargetABI:
    """Detected ABI of the target process. Unknown fields are None / 'unknown', never guessed."""
    status: str = DETECTION_FAILED
    architecture: Optional[str] = None
    word_size: Optional[int] = None          # bits: 32 or 64
    endianness: Optional[str] = None         # "little" / "big"
    libc: str = LIBC_UNKNOWN                 # glibc / musl / unknown
    libc_version: Optional[str] = None
    interpreter: Optional[str] = None        # PT_INTERP path
    libc_path: Optional[str] = None          # mapped libc file used as evidence
    evidence: List[str] = field(default_factory=list)
    error: Optional[str] = None
    kernel_release: Optional[str] = None     # /proc/sys/kernel/osrelease of the TARGET host (read via the adapter)

    @property
    def detected(self) -> bool:
        """True when architecture, word size and endianness are all established."""
        return bool(self.architecture and self.word_size and self.endianness)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "architecture": self.architecture,
            "word_size": self.word_size,
            "endianness": self.endianness,
            "libc": self.libc,
            "libc_version": self.libc_version,
            "interpreter": self.interpreter,
            "libc_path": self.libc_path,
            "evidence": list(self.evidence),
            "error": self.error,
            "kernel_release": self.kernel_release,
        }

    @classmethod
    def from_dict(cls, d: Optional[Dict[str, Any]]) -> "TargetABI":
        d = d or {}
        return cls(
            status=d.get("status", DETECTION_FAILED),
            architecture=d.get("architecture"),
            word_size=d.get("word_size"),
            endianness=d.get("endianness"),
            libc=d.get("libc") or LIBC_UNKNOWN,
            libc_version=d.get("libc_version"),
            interpreter=d.get("interpreter"),
            libc_path=d.get("libc_path"),
            evidence=list(d.get("evidence") or []),
            error=d.get("error"),
            kernel_release=d.get("kernel_release"),
        )


@dataclass
class SupportDecision:
    feature: str
    status: str
    message: str
    architecture: Optional[str] = None
    libc: Optional[str] = None

    @property
    def supported(self) -> bool:
        return self.status == SUPPORT_SUPPORTED

    def to_dict(self) -> Dict[str, Any]:
        return {
            "feature": self.feature,
            "status": self.status,
            "message": self.message,
            "architecture": self.architecture,
            "libc": self.libc,
        }


# --------------------------------------------------------------------------------------
# Parsing helpers
# --------------------------------------------------------------------------------------
def parse_elf_header(raw: bytes) -> Dict[str, Any]:
    """Parse class / endianness / machine / PT_INTERP out of the start of an ELF file.

    Raises ValueError on anything that is not a well-formed ELF prefix.
    """
    if not raw or len(raw) < 20 or raw[:4] != b"\x7fELF":
        raise ValueError("not an ELF image")
    ei_class, ei_data = raw[4], raw[5]
    if ei_class not in (1, 2):
        raise ValueError(f"unsupported ELF class {ei_class}")
    if ei_data not in (1, 2):
        raise ValueError(f"unsupported ELF data encoding {ei_data}")
    endian = "<" if ei_data == 1 else ">"
    is_64 = ei_class == 2
    e_machine = struct.unpack_from(endian + "H", raw, 18)[0]
    out: Dict[str, Any] = {
        "word_size": 64 if is_64 else 32,
        "endianness": "little" if ei_data == 1 else "big",
        "e_machine": e_machine,
        "architecture": _E_MACHINE.get(e_machine, f"machine_0x{e_machine:04x}"),
        "interpreter": None,
    }
    if e_machine == 243:
        out["architecture"] = "riscv64" if is_64 else "riscv"
    try:
        if is_64:
            if len(raw) < 64:
                return out
            e_phoff = struct.unpack_from(endian + "Q", raw, 32)[0]
            e_phentsize, e_phnum = struct.unpack_from(endian + "HH", raw, 54)
        else:
            if len(raw) < 52:
                return out
            e_phoff = struct.unpack_from(endian + "I", raw, 28)[0]
            e_phentsize, e_phnum = struct.unpack_from(endian + "HH", raw, 42)
        for i in range(min(e_phnum, 64)):
            off = e_phoff + i * e_phentsize
            if is_64:
                if off + 56 > len(raw):
                    break
                p_type, _fl, p_offset, _va, _pa, p_filesz = struct.unpack_from(endian + "IIQQQQ", raw, off)
            else:
                if off + 32 > len(raw):
                    break
                p_type, p_offset, _va, _pa, p_filesz = struct.unpack_from(endian + "IIIII", raw, off)
            if p_type == 3 and 0 < p_filesz < 4096 and p_offset + p_filesz <= len(raw):  # PT_INTERP
                out["interpreter"] = raw[p_offset:p_offset + p_filesz].split(b"\x00", 1)[0].decode("utf-8", "replace")
                break
    except struct.error:
        pass
    return out


_GLIBC_FILE_RE = re.compile(r"^(?:libc\.so\.6|libc-(\d+\.\d+(?:\.\d+)?)\.so|ld-linux[\w.+-]*\.so[\w.]*|ld-(\d+\.\d+(?:\.\d+)?)\.so|ld\.so\.1|ld64\.so\.[12])$")
_MUSL_FILE_RE = re.compile(r"^(?:ld-musl-[\w]+\.so\.\d+|libc\.musl-[\w]+\.so\.\d+)$")
_GLIBC_BANNER_RE = re.compile(rb"GNU C Library[^\n\x00]{0,120}?version (\d+\.\d+(?:\.\d+)?)")
_MAX_VERSION_SCAN_BYTES = 4 * 1024 * 1024


def _basename(path: str) -> str:
    return path.rsplit("/", 1)[-1]


def _classify_libc_name(path: str) -> Tuple[str, Optional[str]]:
    base = _basename(path)
    if _MUSL_FILE_RE.match(base):
        return LIBC_MUSL, None
    m = _GLIBC_FILE_RE.match(base)
    if m:
        return LIBC_GLIBC, m.group(1) or m.group(2)
    return LIBC_UNKNOWN, None


def detect_target_abi(
    adapter: Any, pid: int, probe_version: bool = True, maps: Optional[List[Dict[str, Any]]] = None
) -> TargetABI:
    """Detect the ABI of process ``pid`` as seen through ``adapter`` (local or remote).

    Never consults the platform of the machine running this code.  Returns a TargetABI whose
    ``status`` is FAILED when architecture / word size / endianness cannot be established.
    ``maps`` lets a caller that already holds /proc/PID/maps avoid a second read.
    ``probe_version=False`` skips the (local-only) scan of the libc file for the glibc version.
    """
    abi = TargetABI()
    reader = getattr(adapter, "read_target_file", None)
    if callable(reader):  # kernel release of the target host (local or remote); anything not a release string is dropped
        try:
            raw = reader(int(pid), "/proc/sys/kernel/osrelease", 256)
            txt = raw.decode("ascii").strip() if raw else ""
            abi.kernel_release = txt if re.fullmatch(r"\d+\.\d+[\w.+~-]*", txt) else None
        except Exception:  # noqa: BLE001
            abi.kernel_release = None
    hdr: Optional[bytes] = None
    if callable(reader):
        try:
            hdr = reader(int(pid), f"/proc/{int(pid)}/exe", 65536)
        except Exception as exc:  # noqa: BLE001 - detection must never raise
            abi.evidence.append(f"exe header read failed: {exc}")
    if not hdr:
        abi.error = "cannot read ELF header of the target executable"
        return abi
    try:
        parsed = parse_elf_header(hdr)
    except ValueError as exc:
        abi.error = f"target executable is not a parsable ELF: {exc}"
        return abi
    abi.architecture = parsed["architecture"]
    abi.word_size = parsed["word_size"]
    abi.endianness = parsed["endianness"]
    abi.interpreter = parsed["interpreter"]
    abi.evidence.append(
        f"ELF header: {abi.architecture}, {abi.word_size}-bit, {abi.endianness}-endian"
    )

    # --- libc kind: interpreter path, then the mapped libc file --------------------------
    votes: Dict[str, List[str]] = {LIBC_GLIBC: [], LIBC_MUSL: []}
    version: Optional[str] = None
    if abi.interpreter:
        kind, ver = _classify_libc_name(abi.interpreter)
        if kind != LIBC_UNKNOWN:
            votes[kind].append(f"PT_INTERP {abi.interpreter}")
            version = version or ver
        else:
            abi.evidence.append(f"PT_INTERP {abi.interpreter} not recognised")
    else:
        abi.evidence.append("no PT_INTERP (static executable or no dynamic loader)")

    libc_path: Optional[str] = None
    if maps is None:
        try:
            maps = adapter.get_proc_maps(int(pid)) or []
        except Exception as exc:  # noqa: BLE001
            maps = []
            abi.evidence.append(f"maps read failed: {exc}")
    seen = set()
    for m in maps:
        p = (m.get("pathname") or m.get("name") or "").strip()
        if not p or p in seen or not p.startswith("/"):
            continue
        seen.add(p)
        kind, ver = _classify_libc_name(p)
        if kind == LIBC_UNKNOWN:
            continue
        votes[kind].append(f"mapped {p}")
        base = _basename(p)
        if kind == LIBC_MUSL or base.startswith("libc"):
            libc_path = libc_path or p
        version = version or ver

    if votes[LIBC_GLIBC] and votes[LIBC_MUSL]:
        abi.libc = LIBC_UNKNOWN
        abi.evidence.append("conflicting libc evidence (glibc and musl markers both present)")
    elif votes[LIBC_MUSL]:
        abi.libc = LIBC_MUSL
    elif votes[LIBC_GLIBC]:
        abi.libc = LIBC_GLIBC
    for kind in (LIBC_GLIBC, LIBC_MUSL):
        abi.evidence.extend(votes[kind])
    abi.libc_path = libc_path

    # glibc version: from a versioned file name, else from the banner inside the mapped libc
    if probe_version and abi.libc == LIBC_GLIBC and not version and libc_path and callable(reader) and not _is_remote(adapter):
        try:
            blob = reader(int(pid), libc_path, _MAX_VERSION_SCAN_BYTES)
            bm = _GLIBC_BANNER_RE.search(blob or b"")
            if bm:
                version = bm.group(1).decode("ascii", "replace")
                abi.evidence.append(f"glibc banner in {libc_path}")
        except Exception:  # noqa: BLE001
            pass
    abi.libc_version = version if abi.libc == LIBC_GLIBC else None
    abi.status = DETECTION_DETECTED
    return abi


def _is_remote(adapter: Any) -> bool:
    try:
        return bool(adapter.is_remote())
    except Exception:  # noqa: BLE001
        return True


# --------------------------------------------------------------------------------------
# Support decisions
# --------------------------------------------------------------------------------------
def check_support(abi: Optional[TargetABI], feature: str) -> SupportDecision:
    """Consult :data:`SUPPORT_TABLE` for ``feature`` on the detected target ABI."""
    if feature not in SUPPORT_TABLE:
        return SupportDecision(feature, SUPPORT_NOT_SUPPORTED_ON_TARGET, f"{feature}: unknown feature")
    if abi is None or not abi.detected:
        why = (abi.error if abi is not None and abi.error else "target ABI was not detected")
        return SupportDecision(
            feature, SUPPORT_INCONCLUSIVE,
            f"{feature}: inconclusive - target ABI detection failed ({why})",
        )
    rows = SUPPORT_TABLE[feature]
    libc_needed = any(r[1] is not _ANY for r in rows if r[0] == abi.architecture)
    for arch, libc, word, endian in rows:
        if arch != abi.architecture:
            continue
        if word is not _ANY and word != abi.word_size:
            continue
        if endian is not _ANY and endian != abi.endianness:
            continue
        if libc is not _ANY and libc != abi.libc:
            continue
        return SupportDecision(feature, SUPPORT_SUPPORTED, "supported", abi.architecture, abi.libc)
    if libc_needed and abi.libc == LIBC_UNKNOWN:
        return SupportDecision(
            feature, SUPPORT_INCONCLUSIVE,
            f"{feature}: inconclusive - libc of the target could not be identified ({abi.architecture})",
            abi.architecture, abi.libc,
        )
    return SupportDecision(
        feature, SUPPORT_NOT_SUPPORTED_ON_TARGET,
        f"{feature}: not supported on this target ({abi.architecture}/{abi.libc}, "
        f"{abi.word_size}-bit {abi.endianness}-endian)",
        abi.architecture, abi.libc,
    )


def syscall_name(abi: Optional[TargetABI], number: int) -> Optional[str]:
    """Name of syscall ``number`` for the target ABI.

    Returns None when the table for this target is not available (unsupported or undetected
    ABI).  For a supported ABI an unlisted number yields ``syscall_<n>`` (still correct, just
    not named).
    """
    if not check_support(abi, FEATURE_SYSCALL_NAMES).supported:
        return None
    table = SYSCALL_TABLES.get(abi.architecture or "", {})
    return table.get(number, f"syscall_{number}")


def abi_support_summary(abi: Optional[TargetABI], features: Optional[List[str]] = None) -> Dict[str, Dict[str, Any]]:
    """Per-feature decisions as plain dicts for inclusion in results."""
    return {f: check_support(abi, f).to_dict() for f in (features or list(SUPPORT_TABLE))}
