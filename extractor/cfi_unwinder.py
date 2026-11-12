"""CFI (DWARF call-frame information) based call-stack unwinding for a live process (IMP-011).

The target is never stopped: the only register state available for a thread is what the kernel
publishes in ``/proc/PID/task/TID/syscall`` for a thread blocked in a system call (stack pointer and
program counter).  Everything else is read from the target's stack through the caller supplied,
budget-accounted, non-stopping ``read_memory`` callback.

Unwinding tiers, reported per frame in ``unwind``:

``registers``
    frame 0 of a blocked thread: PC/SP reported by the kernel (exact).
``cfi``
    the frame was reached by executing the CFA program of the callee's FDE (``.eh_frame`` /
    ``.debug_frame`` of the module mapped at that PC, with that module's own load bias) - exact.
``frame_pointer``
    the callee's CFA depended on a frame-pointer register (rbp / x29) whose value is not known
    (only SP/PC are published by the kernel) or the callee had no FDE: the frame record
    ``[fp] = caller fp, [fp + ptr] = return address`` was used, and the return address was
    accepted only if the instruction before it is a call whose direct target is the callee
    (or an indirect call).  Deterministic, but relies on the frame-record convention.
``scan_estimated``
    CFI and the frame record could not continue: the stack was scanned for a word that is a
    return address (preceded by a call instruction, call target consistent with the callee when
    decodable).  Estimated - may be wrong.
``cfi_after_scan``
    CFI resumed from a scanned anchor; exact relative to the anchor, but the anchor is estimated.
``running_sample_estimated``
    the thread was running on a CPU (no SP/PC published): the frames come from a two-read
    sample of the thread's stack; see :meth:`CfiUnwinder.sample_running`.

Every frame carries ``estimated`` (True for anything derived from a scan or a running sample).

Architectures: x86_64 and aarch64 are implemented.  Others (arm 32-bit, ...) are refused with
:data:`UNWIND_UNSUPPORTED_ARCH`; callers report that instead of guessing.
"""

from __future__ import annotations

import bisect
import os
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

# --------------------------------------------------------------------------------------
# Public status values
# --------------------------------------------------------------------------------------
UNWIND_REGISTERS = "registers"
UNWIND_CFI = "cfi"
UNWIND_FRAME_POINTER = "frame_pointer"
UNWIND_SCAN = "scan_estimated"
UNWIND_CFI_AFTER_SCAN = "cfi_after_scan"
UNWIND_RUNNING = "running_sample_estimated"

EXACT_METHODS = frozenset({UNWIND_REGISTERS, UNWIND_CFI, UNWIND_FRAME_POINTER})

STATUS_COMPLETE = "COMPLETE"                       # reached the outermost frame without estimation
STATUS_TRUNCATED = "TRUNCATED"                     # exact frames only, but stopped before the outermost frame
STATUS_PARTIAL_ESTIMATED = "PARTIAL_ESTIMATED"     # some frames come from the scan fallback
STATUS_RUNNING_SAMPLE = "RUNNING_SAMPLE_ESTIMATED"
STATUS_NO_REGISTERS = "NO_REGISTERS"
UNWIND_UNSUPPORTED_ARCH = "UNSUPPORTED_ARCHITECTURE"

STOP_OUTERMOST = "outermost_frame"                 # RA rule undefined / RA == 0: clean bottom of the stack
_OUTERMOST_ZERO_RA = "outermost_zero_return_address"  # running samples: weaker evidence than "RA undefined"

# --------------------------------------------------------------------------------------
# Architecture descriptions (DWARF register numbering)
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class ArchSpec:
    name: str
    ptr_size: int
    sp_reg: int
    fp_reg: int
    ra_reg: int
    callee_saved: Tuple[int, ...]
    reg_names: Dict[int, str]
    ra_in_register: bool        # True when a call leaves the return address in a register (aarch64 x30)


_X86_64_NAMES = {0: "rax", 1: "rdx", 2: "rcx", 3: "rbx", 4: "rsi", 5: "rdi", 6: "rbp", 7: "rsp",
                 8: "r8", 9: "r9", 10: "r10", 11: "r11", 12: "r12", 13: "r13", 14: "r14", 15: "r15",
                 16: "rip"}
_AARCH64_NAMES = {i: f"x{i}" for i in range(31)}
_AARCH64_NAMES[31] = "sp"

ARCH_SPECS: Dict[str, ArchSpec] = {
    "x86_64": ArchSpec("x86_64", 8, sp_reg=7, fp_reg=6, ra_reg=16,
                       callee_saved=(3, 6, 12, 13, 14, 15), reg_names=_X86_64_NAMES,
                       ra_in_register=False),
    "aarch64": ArchSpec("aarch64", 8, sp_reg=31, fp_reg=29, ra_reg=30,
                        callee_saved=tuple(range(19, 30)), reg_names=_AARCH64_NAMES,
                        ra_in_register=True),
}

_EM_TO_ARCH = {62: "x86_64", 183: "aarch64", 40: "arm", 3: "x86"}


def arch_supported(arch: Optional[str]) -> bool:
    return bool(arch) and arch in ARCH_SPECS


# --------------------------------------------------------------------------------------
# Small decoding helpers
# --------------------------------------------------------------------------------------
def _uleb(data: bytes, pos: int) -> Tuple[int, int]:
    result = 0
    shift = 0
    while True:
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if not b & 0x80:
            return result, pos


def _sleb(data: bytes, pos: int) -> Tuple[int, int]:
    result = 0
    shift = 0
    while True:
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if not b & 0x80:
            if b & 0x40:
                result -= 1 << shift
            return result, pos


DW_EH_PE_omit = 0xFF


def read_encoded(data: bytes, pos: int, enc: int, ptr_size: int, endian: str, section_vaddr: int,
                 datarel: int = 0) -> Tuple[Optional[int], int]:
    """Decode a DW_EH_PE_* encoded pointer at ``data[pos]``. Returns (value, new_pos)."""
    if enc == DW_EH_PE_omit:
        return None, pos
    e = "<" if endian == "little" else ">"
    fmt = enc & 0x0F
    app = enc & 0x70
    if app == 0x50:  # aligned
        pos = (pos + ptr_size - 1) & ~(ptr_size - 1)
    start = pos
    if fmt == 0x00:
        val = struct.unpack_from(e + ("Q" if ptr_size == 8 else "I"), data, pos)[0]
        pos += ptr_size
    elif fmt == 0x01:
        val, pos = _uleb(data, pos)
    elif fmt == 0x02:
        val = struct.unpack_from(e + "H", data, pos)[0]
        pos += 2
    elif fmt == 0x03:
        val = struct.unpack_from(e + "I", data, pos)[0]
        pos += 4
    elif fmt == 0x04:
        val = struct.unpack_from(e + "Q", data, pos)[0]
        pos += 8
    elif fmt == 0x09:
        val, pos = _sleb(data, pos)
    elif fmt == 0x0A:
        val = struct.unpack_from(e + "h", data, pos)[0]
        pos += 2
    elif fmt == 0x0B:
        val = struct.unpack_from(e + "i", data, pos)[0]
        pos += 4
    elif fmt == 0x0C:
        val = struct.unpack_from(e + "q", data, pos)[0]
        pos += 8
    else:
        raise ValueError(f"unsupported pointer encoding 0x{enc:02x}")
    if app == 0x10:  # pcrel
        val += section_vaddr + start
    elif app == 0x30:  # datarel
        val += datarel
    return val & ((1 << (8 * ptr_size)) - 1), pos


# --------------------------------------------------------------------------------------
# CFI records and the CFA program interpreter
# --------------------------------------------------------------------------------------
@dataclass
class Cie:
    offset: int
    version: int
    augmentation: str
    code_align: int
    data_align: int
    ra_reg: int
    fde_enc: int
    lsda_enc: int
    signal_frame: bool
    initial_instructions: bytes
    address_size: int


@dataclass
class Fde:
    offset: int
    cie: Cie
    pc_begin: int
    pc_end: int
    instructions: bytes
    source: str  # ".eh_frame" / ".debug_frame"


# Register rule kinds
R_UNDEFINED = "undefined"
R_SAME = "same_value"
R_OFFSET = "offset"
R_VAL_OFFSET = "val_offset"
R_REGISTER = "register"
R_EXPRESSION = "expression"
R_VAL_EXPRESSION = "val_expression"


@dataclass
class CfiRow:
    loc: int
    cfa_reg: Optional[int] = None
    cfa_offset: int = 0
    cfa_expr: Optional[bytes] = None
    rules: Dict[int, Tuple[str, Any]] = field(default_factory=dict)
    ra_signed: bool = False          # aarch64 DW_CFA_AARCH64_negate_ra_state in effect
    unsupported: List[str] = field(default_factory=list)

    def copy(self) -> "CfiRow":
        return CfiRow(self.loc, self.cfa_reg, self.cfa_offset, self.cfa_expr, dict(self.rules),
                      self.ra_signed, list(self.unsupported))


class CfiProgramError(Exception):
    pass


def execute_cfa_program(fde: Fde, target_pc: Optional[int], arch: str = "x86_64",
                        ptr_size: int = 8, endian: str = "little",
                        section_vaddr: int = 0) -> List[CfiRow]:
    """Execute CIE initial instructions + FDE instructions.

    With ``target_pc`` returns ``[row]`` - the row in effect at that (link-time) PC.  With
    ``target_pc=None`` returns every row (one per location change), for table dumps / oracles.
    """
    cie = fde.cie
    rows: List[CfiRow] = []
    row = CfiRow(loc=fde.pc_begin)
    initial_rules: Dict[int, Tuple[str, Any]] = {}
    state_stack: List[CfiRow] = []

    def run(prog: bytes, is_initial: bool) -> bool:
        nonlocal row
        pos = 0
        n = len(prog)
        while pos < n:
            op = prog[pos]
            pos += 1
            hi = op & 0xC0
            lo = op & 0x3F
            new_loc: Optional[int] = None
            if hi == 0x40:  # advance_loc
                new_loc = row.loc + lo * cie.code_align
            elif hi == 0x80:  # offset
                off, pos = _uleb(prog, pos)
                row.rules[lo] = (R_OFFSET, off * cie.data_align)
            elif hi == 0xC0:  # restore
                if lo in initial_rules:
                    row.rules[lo] = initial_rules[lo]
                else:
                    row.rules.pop(lo, None)
            elif op == 0x00:  # nop
                pass
            elif op == 0x01:  # set_loc
                v, pos = read_encoded(prog, pos, cie.fde_enc if fde.source == ".eh_frame" else 0x00,
                                      ptr_size, endian, section_vaddr)
                new_loc = v
            elif op == 0x02:
                new_loc = row.loc + prog[pos] * cie.code_align
                pos += 1
            elif op == 0x03:
                new_loc = row.loc + struct.unpack_from(("<" if endian == "little" else ">") + "H", prog, pos)[0] * cie.code_align
                pos += 2
            elif op == 0x04:
                new_loc = row.loc + struct.unpack_from(("<" if endian == "little" else ">") + "I", prog, pos)[0] * cie.code_align
                pos += 4
            elif op == 0x05:  # offset_extended
                reg, pos = _uleb(prog, pos)
                off, pos = _uleb(prog, pos)
                row.rules[reg] = (R_OFFSET, off * cie.data_align)
            elif op == 0x06:  # restore_extended
                reg, pos = _uleb(prog, pos)
                if reg in initial_rules:
                    row.rules[reg] = initial_rules[reg]
                else:
                    row.rules.pop(reg, None)
            elif op == 0x07:  # undefined
                reg, pos = _uleb(prog, pos)
                row.rules[reg] = (R_UNDEFINED, None)
            elif op == 0x08:  # same_value
                reg, pos = _uleb(prog, pos)
                row.rules[reg] = (R_SAME, None)
            elif op == 0x09:  # register
                reg, pos = _uleb(prog, pos)
                reg2, pos = _uleb(prog, pos)
                row.rules[reg] = (R_REGISTER, reg2)
            elif op == 0x0A:  # remember_state
                state_stack.append(row.copy())
            elif op == 0x0B:  # restore_state
                if not state_stack:
                    raise CfiProgramError("DW_CFA_restore_state with empty stack")
                saved = state_stack.pop()
                loc = row.loc
                row = saved
                row.loc = loc
            elif op == 0x0C:  # def_cfa
                reg, pos = _uleb(prog, pos)
                off, pos = _uleb(prog, pos)
                row.cfa_reg, row.cfa_offset, row.cfa_expr = reg, off, None
            elif op == 0x0D:  # def_cfa_register
                reg, pos = _uleb(prog, pos)
                row.cfa_reg, row.cfa_expr = reg, None
            elif op == 0x0E:  # def_cfa_offset
                off, pos = _uleb(prog, pos)
                row.cfa_offset = off
            elif op == 0x0F:  # def_cfa_expression
                ln, pos = _uleb(prog, pos)
                row.cfa_expr = bytes(prog[pos:pos + ln])
                row.cfa_reg = None
                pos += ln
            elif op == 0x10:  # expression
                reg, pos = _uleb(prog, pos)
                ln, pos = _uleb(prog, pos)
                row.rules[reg] = (R_EXPRESSION, bytes(prog[pos:pos + ln]))
                pos += ln
            elif op == 0x11:  # offset_extended_sf
                reg, pos = _uleb(prog, pos)
                off, pos = _sleb(prog, pos)
                row.rules[reg] = (R_OFFSET, off * cie.data_align)
            elif op == 0x12:  # def_cfa_sf
                reg, pos = _uleb(prog, pos)
                off, pos = _sleb(prog, pos)
                row.cfa_reg, row.cfa_offset, row.cfa_expr = reg, off * cie.data_align, None
            elif op == 0x13:  # def_cfa_offset_sf
                off, pos = _sleb(prog, pos)
                row.cfa_offset = off * cie.data_align
            elif op == 0x14:  # val_offset
                reg, pos = _uleb(prog, pos)
                off, pos = _uleb(prog, pos)
                row.rules[reg] = (R_VAL_OFFSET, off * cie.data_align)
            elif op == 0x15:  # val_offset_sf
                reg, pos = _uleb(prog, pos)
                off, pos = _sleb(prog, pos)
                row.rules[reg] = (R_VAL_OFFSET, off * cie.data_align)
            elif op == 0x16:  # val_expression
                reg, pos = _uleb(prog, pos)
                ln, pos = _uleb(prog, pos)
                row.rules[reg] = (R_VAL_EXPRESSION, bytes(prog[pos:pos + ln]))
                pos += ln
            elif op == 0x2D:
                if arch == "aarch64":  # DW_CFA_AARCH64_negate_ra_state
                    row.ra_signed = not row.ra_signed
                else:  # DW_CFA_GNU_window_save (SPARC) - meaningless here
                    row.unsupported.append("DW_CFA_GNU_window_save")
            elif op == 0x2E:  # GNU_args_size
                _, pos = _uleb(prog, pos)
            elif op == 0x2F:  # GNU_negative_offset_extended
                reg, pos = _uleb(prog, pos)
                off, pos = _uleb(prog, pos)
                row.rules[reg] = (R_OFFSET, -off * cie.data_align)
            else:
                raise CfiProgramError(f"unknown DW_CFA opcode 0x{op:02x}")
            if new_loc is not None:
                if is_initial:
                    raise CfiProgramError("location advance in CIE initial instructions")
                if target_pc is not None and new_loc > target_pc:
                    return True
                if target_pc is None and new_loc != row.loc:
                    rows.append(row.copy())
                row.loc = new_loc
        return False

    run(cie.initial_instructions, True)
    initial_rules = dict(row.rules)
    row.loc = fde.pc_begin
    run(fde.instructions, False)
    if target_pc is not None:
        return [row]
    rows.append(row.copy())
    return rows


# --------------------------------------------------------------------------------------
# ELF image (local file) with CFI, symbols and code bytes
# --------------------------------------------------------------------------------------
@dataclass
class _Section:
    name: str
    sh_type: int
    addr: int
    offset: int
    size: int
    link: int
    entsize: int


class ElfImage:
    """Read-only view of an ELF file: sections, PT_LOADs, CFI tables, function symbols."""

    def __init__(self, path: str, data: bytes):
        self.path = path
        self.data = data
        if data[:4] != b"\x7fELF":
            raise ValueError(f"{path}: not an ELF file")
        self.is64 = data[4] == 2
        self.endian = "little" if data[5] == 1 else "big"
        e = "<" if self.endian == "little" else ">"
        self._e = e
        self.ptr_size = 8 if self.is64 else 4
        if self.is64:
            (self.e_type, self.e_machine) = struct.unpack_from(e + "HH", data, 16)
            e_phoff, e_shoff = struct.unpack_from(e + "QQ", data, 32)
            e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(e + "HHHHH", data, 54)
        else:
            (self.e_type, self.e_machine) = struct.unpack_from(e + "HH", data, 16)
            e_phoff, e_shoff = struct.unpack_from(e + "II", data, 28)
            e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(e + "HHHHH", data, 42)
        self.arch = _EM_TO_ARCH.get(self.e_machine, f"machine_{self.e_machine}")
        self.segments: List[Tuple[int, int, int, int, int, int]] = []  # (type, flags, offset, vaddr, filesz, memsz)
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            if self.is64:
                p_type, p_flags, p_offset, p_vaddr, _pa, p_filesz, p_memsz = struct.unpack_from(e + "IIQQQQQ", data, off)
            else:
                p_type, p_offset, p_vaddr, _pa, p_filesz, p_memsz, p_flags = struct.unpack_from(e + "IIIIIII", data, off)
            self.segments.append((p_type, p_flags, p_offset, p_vaddr, p_filesz, p_memsz))
        self.sections: Dict[str, _Section] = {}
        self._sections_list: List[_Section] = []
        if e_shoff and e_shnum:
            raw = []
            for i in range(e_shnum):
                off = e_shoff + i * e_shentsize
                if off + e_shentsize > len(data):
                    break
                if self.is64:
                    sh_name, sh_type, _fl, sh_addr, sh_offset, sh_size, sh_link, _info, _al, sh_entsize = struct.unpack_from(e + "IIQQQQIIQQ", data, off)
                else:
                    sh_name, sh_type, _fl, sh_addr, sh_offset, sh_size, sh_link, _info, _al, sh_entsize = struct.unpack_from(e + "IIIIIIIIII", data, off)
                raw.append((sh_name, sh_type, sh_addr, sh_offset, sh_size, sh_link, sh_entsize))
            if e_shstrndx < len(raw):
                stro = raw[e_shstrndx][3]
                for (nm, ty, ad, of, sz, lk, es) in raw:
                    end = data.find(b"\x00", stro + nm)
                    name = data[stro + nm:end].decode("ascii", "replace")
                    sec = _Section(name, ty, ad, of, sz, lk, es)
                    self._sections_list.append(sec)
                    if name not in self.sections:
                        self.sections[name] = sec
        self._cie_cache: Dict[Tuple[str, int], Cie] = {}
        self._fde_index: Dict[str, Optional[List[Tuple[int, int, int]]]] = {}
        self._hdr_table: Optional[Tuple[int, int, int]] = None  # (table file offset, count, datarel base)
        self._hdr_checked = False
        self._symbols: Optional[List[Tuple[int, int, str]]] = None
        self._symbol_addrs: List[int] = []
        self._lock = threading.Lock()

    # -- address mapping ---------------------------------------------------------------
    def vaddr_to_offset(self, vaddr: int, size: int = 1) -> Optional[int]:
        for p_type, _fl, p_offset, p_vaddr, p_filesz, _ms in self.segments:
            if p_type == 1 and p_vaddr <= vaddr and vaddr + size <= p_vaddr + p_filesz:
                return p_offset + (vaddr - p_vaddr)
        return None

    def read_vaddr(self, vaddr: int, size: int) -> Optional[bytes]:
        off = self.vaddr_to_offset(vaddr, size)
        if off is None or off + size > len(self.data):
            return None
        return self.data[off:off + size]

    def load_bias_for_mapping(self, map_start: int, map_offset: int) -> Optional[int]:
        """Load bias such that runtime = link + bias, from one /proc/PID/maps line of this file."""
        for p_type, _fl, p_offset, p_vaddr, p_filesz, _ms in self.segments:
            if p_type != 1:
                continue
            page_off = p_offset & ~0xFFF
            if page_off <= map_offset < p_offset + max(p_filesz, 1):
                return map_start - (map_offset + (p_vaddr - p_offset))
        return None

    def section_containing(self, vaddr: int) -> Optional[str]:
        for s in self._sections_list:
            if s.addr and s.addr <= vaddr < s.addr + s.size:
                return s.name
        return None

    def is_plt(self, vaddr: int) -> bool:
        name = self.section_containing(vaddr) or ""
        return name.startswith(".plt") or name == ".iplt"

    # -- CFI -----------------------------------------------------------------------------
    def _parse_cie(self, sec_name: str, sec: _Section, off: int) -> Cie:
        key = (sec_name, off)
        c = self._cie_cache.get(key)
        if c is not None:
            return c
        d = self.data
        e = self._e
        base = sec.offset
        pos = base + off
        length = struct.unpack_from(e + "I", d, pos)[0]
        pos += 4
        is64dw = False
        if length == 0xFFFFFFFF:
            length = struct.unpack_from(e + "Q", d, pos)[0]
            pos += 8
            is64dw = True
        end = pos + length
        pos += 8 if is64dw else 4  # CIE id
        version = d[pos]
        pos += 1
        aug_end = d.index(b"\x00", pos)
        aug = d[pos:aug_end].decode("ascii", "replace")
        pos = aug_end + 1
        address_size = self.ptr_size
        if sec_name == ".debug_frame" and version >= 4:
            address_size = d[pos]
            pos += 2  # address_size, segment_selector_size
        if "eh" in aug:
            pos += self.ptr_size
        code_align, pos = _uleb(d, pos)
        data_align, pos = _sleb(d, pos)
        if version == 1:
            ra_reg = d[pos]
            pos += 1
        else:
            ra_reg, pos = _uleb(d, pos)
        fde_enc = 0x00
        lsda_enc = DW_EH_PE_omit
        signal = False
        if aug.startswith("z"):
            aug_len, pos = _uleb(d, pos)
            aug_data_end = pos + aug_len
            for ch in aug[1:]:
                if ch == "R":
                    fde_enc = d[pos]
                    pos += 1
                elif ch == "L":
                    lsda_enc = d[pos]
                    pos += 1
                elif ch == "P":
                    penc = d[pos]
                    pos += 1
                    _, pos = read_encoded(d, pos, penc & 0x7F, self.ptr_size, self.endian, sec.addr - sec.offset)
                elif ch == "S":
                    signal = True
                elif ch in ("B", "G"):
                    pass
            pos = aug_data_end
        elif "S" in aug:
            signal = True
        c = Cie(off, version, aug, code_align, data_align, ra_reg, fde_enc, lsda_enc, signal,
                bytes(d[pos:end]), address_size)
        self._cie_cache[key] = c
        return c

    def _parse_fde_at(self, sec_name: str, off: int) -> Optional[Fde]:
        sec = self.sections.get(sec_name)
        if sec is None or sec.sh_type == 8:  # SHT_NOBITS
            return None
        d = self.data
        e = self._e
        base = sec.offset
        pos = base + off
        length = struct.unpack_from(e + "I", d, pos)[0]
        pos += 4
        is64dw = False
        if length == 0xFFFFFFFF:
            length = struct.unpack_from(e + "Q", d, pos)[0]
            pos += 8
            is64dw = True
        if length == 0:
            return None
        end = pos + length
        id_pos = pos
        cie_id = struct.unpack_from(e + ("Q" if is64dw else "I"), d, pos)[0]
        pos += 8 if is64dw else 4
        if sec_name == ".eh_frame":
            if cie_id == 0:
                return None
            cie_off = (id_pos - base) - cie_id
        else:
            if cie_id in (0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF):
                return None
            cie_off = cie_id
        cie = self._parse_cie(sec_name, sec, cie_off)
        vbase = sec.addr - sec.offset  # pcrel: vaddr of byte at file offset X is X + vbase
        if sec_name == ".eh_frame":
            pc_begin, pos = read_encoded(d, pos, cie.fde_enc, self.ptr_size, self.endian, vbase)
            pc_range, pos = read_encoded(d, pos, cie.fde_enc & 0x0F, self.ptr_size, self.endian, 0)
            if cie.augmentation.startswith("z"):
                alen, pos = _uleb(d, pos)
                pos += alen
        else:
            asz = cie.address_size
            fmt = e + ("Q" if asz == 8 else "I")
            pc_begin = struct.unpack_from(fmt, d, pos)[0]
            pc_range = struct.unpack_from(fmt, d, pos + asz)[0]
            pos += 2 * asz
        return Fde(off, cie, pc_begin or 0, (pc_begin or 0) + (pc_range or 0), bytes(d[pos:end]), sec_name)

    def _build_full_index(self, sec_name: str) -> List[Tuple[int, int, int]]:
        """[(pc_begin, pc_end, fde_offset)] sorted, by walking every entry of the section."""
        out: List[Tuple[int, int, int]] = []
        sec = self.sections.get(sec_name)
        if sec is None or sec.sh_type == 8 or sec.size == 0:
            return out
        d = self.data
        e = self._e
        off = 0
        while off + 4 <= sec.size:
            pos = sec.offset + off
            length = struct.unpack_from(e + "I", d, pos)[0]
            hdr = 4
            if length == 0xFFFFFFFF:
                length = struct.unpack_from(e + "Q", d, pos + 4)[0]
                hdr = 12
            if length == 0:
                if sec_name == ".eh_frame":
                    break  # terminator
                off += hdr
                continue
            try:
                fde = self._parse_fde_at(sec_name, off)
            except Exception:  # noqa: BLE001 - a malformed entry must not kill the whole table
                fde = None
            if fde is not None and fde.pc_end > fde.pc_begin:
                out.append((fde.pc_begin, fde.pc_end, off))
            off += hdr + length
        out.sort()
        return out

    def _check_hdr(self) -> None:
        if self._hdr_checked:
            return
        self._hdr_checked = True
        hdr = self.sections.get(".eh_frame_hdr")
        if hdr is None or hdr.size < 12:
            return
        d = self.data
        pos = hdr.offset
        version, ptr_enc, cnt_enc, tbl_enc = d[pos], d[pos + 1], d[pos + 2], d[pos + 3]
        if version != 1 or tbl_enc != 0x3B:  # only the (universal) datarel|sdata4 table is used
            return
        try:
            _, p = read_encoded(d, pos + 4, ptr_enc, self.ptr_size, self.endian, hdr.addr - hdr.offset, hdr.addr)
            count, p = read_encoded(d, p, cnt_enc, self.ptr_size, self.endian, hdr.addr - hdr.offset, hdr.addr)
        except Exception:  # noqa: BLE001
            return
        if count is None or p + count * 8 > hdr.offset + hdr.size:
            return
        self._hdr_table = (p, count, hdr.addr)

    def find_fde(self, link_pc: int) -> Optional[Fde]:
        """FDE covering ``link_pc`` (link-time address): .eh_frame first, then .debug_frame."""
        eh = self.sections.get(".eh_frame")
        if eh is not None:
            self._check_hdr()
            if self._hdr_table is not None:
                tpos, count, dbase = self._hdr_table
                e = self._e
                lo, hi = 0, count
                while lo < hi:  # last entry with initial_loc <= pc
                    mid = (lo + hi) // 2
                    loc = struct.unpack_from(e + "i", self.data, tpos + mid * 8)[0] + dbase
                    if loc <= link_pc:
                        lo = mid + 1
                    else:
                        hi = mid
                if lo > 0:
                    fde_addr = struct.unpack_from(e + "i", self.data, tpos + (lo - 1) * 8 + 4)[0] + dbase
                    fde = self._parse_fde_at(".eh_frame", fde_addr - eh.addr)
                    if fde is not None and fde.pc_begin <= link_pc < fde.pc_end:
                        return fde
            else:
                fde = self._lookup_index(".eh_frame", link_pc)
                if fde is not None:
                    return fde
        return self._lookup_index(".debug_frame", link_pc)

    def _lookup_index(self, sec_name: str, link_pc: int) -> Optional[Fde]:
        with self._lock:
            idx = self._fde_index.get(sec_name)
            if idx is None:
                idx = self._build_full_index(sec_name)
                self._fde_index[sec_name] = idx
        if not idx:
            return None
        i = bisect.bisect_right(idx, (link_pc, float("inf"), float("inf"))) - 1
        # FDEs do not normally overlap; look at a few predecessors for the rare nested case
        for j in range(i, max(-1, i - 4), -1):
            b, en, off = idx[j]
            if b <= link_pc < en:
                return self._parse_fde_at(sec_name, off)
        return None

    def all_fdes(self) -> List[Fde]:
        out: List[Fde] = []
        for sec_name in (".eh_frame", ".debug_frame"):
            for _b, _e, off in self._build_full_index(sec_name):
                f = self._parse_fde_at(sec_name, off)
                if f is not None:
                    out.append(f)
        return out

    def row_at(self, link_pc: int, fde: Optional[Fde] = None) -> Optional[Tuple[Fde, CfiRow]]:
        fde = fde or self.find_fde(link_pc)
        if fde is None:
            return None
        sec = self.sections.get(fde.source)
        vbase = (sec.addr - sec.offset) if sec else 0
        row = execute_cfa_program(fde, link_pc, self.arch, self.ptr_size, self.endian, vbase)[0]
        return fde, row

    def all_rows(self, fde: Fde) -> List[CfiRow]:
        sec = self.sections.get(fde.source)
        vbase = (sec.addr - sec.offset) if sec else 0
        return execute_cfa_program(fde, None, self.arch, self.ptr_size, self.endian, vbase)

    # -- symbols -------------------------------------------------------------------------
    def _load_symbols(self) -> None:
        if self._symbols is not None:
            return
        syms: Dict[int, Tuple[int, int, str]] = {}

        def collect(img: "ElfImage") -> None:
            for sname in (".symtab", ".dynsym"):
                sec = img.sections.get(sname)
                if sec is None or sec.sh_type == 8 or not sec.entsize:
                    continue
                if sec.link >= len(img._sections_list):
                    continue
                strsec = img._sections_list[sec.link]
                e = img._e
                for i in range(sec.size // sec.entsize):
                    o = sec.offset + i * sec.entsize
                    if img.is64:
                        st_name, st_info, _o, st_shndx, st_value, st_size = struct.unpack_from(e + "IBBHQQ", img.data, o)
                    else:
                        st_name, st_value, st_size, st_info, _o, st_shndx = struct.unpack_from(e + "IIIBBH", img.data, o)
                    if (st_info & 0xF) not in (2, 10) or st_value == 0 or st_shndx == 0:
                        continue
                    so = strsec.offset + st_name
                    end = img.data.find(b"\x00", so)
                    name = img.data[so:end].decode("utf-8", "replace")
                    if not name:
                        continue
                    if self.arch == "arm":
                        st_value &= ~1
                    prev = syms.get(st_value)
                    if prev is None or (prev[1] == 0 and st_size) or (name.startswith("__") is False and prev[2].startswith("__")):
                        syms[st_value] = (st_value, st_size, name)

        collect(self)
        dbg = _find_separate_debug_file(self)
        if dbg is not None:
            try:
                with open(dbg, "rb") as fh:
                    collect(ElfImage(dbg, fh.read()))
            except Exception:  # noqa: BLE001
                pass
        self._symbols = sorted(syms.values())
        self._symbol_addrs = [s[0] for s in self._symbols]

    def symbolize(self, link_addr: int) -> Optional[Tuple[str, int]]:
        """(function name, link-time start) of the FUNC symbol covering ``link_addr``."""
        self._load_symbols()
        assert self._symbols is not None
        i = bisect.bisect_right(self._symbol_addrs, link_addr) - 1
        for j in range(i, max(-1, i - 8), -1):
            start, size, name = self._symbols[j]
            if size and start <= link_addr < start + size:
                return name, start
        return None

    def build_id(self) -> Optional[str]:
        for s in self._sections_list:
            if s.sh_type == 7 and s.name == ".note.gnu.build-id":
                d = self.data
                namesz, descsz, ntype = struct.unpack_from(self._e + "III", d, s.offset)
                desc_off = s.offset + 12 + ((namesz + 3) & ~3)
                return d[desc_off:desc_off + descsz].hex()
        return None


def _find_separate_debug_file(img: ElfImage) -> Optional[str]:
    if ".symtab" in img.sections:
        return None
    bid = img.build_id()
    if bid and len(bid) > 2:
        cand = f"/usr/lib/debug/.build-id/{bid[:2]}/{bid[2:]}.debug"
        if os.path.isfile(cand):
            return cand
    return None


_ELF_CACHE: Dict[Tuple[str, int, int, int, int], ElfImage] = {}
_ELF_CACHE_LOCK = threading.Lock()
_MAX_ELF_BYTES = 768 * 1024 * 1024


def load_elf_image(path: str) -> Optional[ElfImage]:
    """Load (cached by path/inode/size/mtime) a local ELF file; None when unreadable/not ELF."""
    try:
        st = os.stat(path)
    except OSError:
        return None
    key = (path, st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)
    with _ELF_CACHE_LOCK:
        img = _ELF_CACHE.get(key)
    if img is not None:
        return img
    if st.st_size > _MAX_ELF_BYTES:
        return None
    try:
        with open(path, "rb") as fh:
            data = fh.read()
        img = ElfImage(path, data)
    except Exception:  # noqa: BLE001
        return None
    with _ELF_CACHE_LOCK:
        _ELF_CACHE[key] = img
    return img


def clear_elf_cache() -> None:
    with _ELF_CACHE_LOCK:
        _ELF_CACHE.clear()


# --------------------------------------------------------------------------------------
# Call-site decoding (is the instruction before a return address a call? to where?)
# --------------------------------------------------------------------------------------
CALL_DIRECT = "direct"
CALL_INDIRECT = "indirect"


def _x86_modrm_len(b: bytes, i: int) -> Optional[int]:
    """Length of a ModRM(+SIB+disp) starting at b[i]; None when incomplete."""
    if i >= len(b):
        return None
    modrm = b[i]
    mod, rm = modrm >> 6, modrm & 7
    n = 1
    if mod == 3:
        return n
    if rm == 4:
        if i + 1 >= len(b):
            return None
        sib = b[i + 1]
        n += 1
        if mod == 0 and (sib & 7) == 5:
            n += 4
    elif mod == 0 and rm == 5:
        n += 4
    if mod == 1:
        n += 1
    elif mod == 2:
        n += 4
    return n


def decode_call_before(arch: str, code: bytes, ra: int, endian: str = "little") -> Tuple[Optional[str], Optional[int]]:
    """``code`` holds the bytes immediately preceding ``ra``.  Returns (kind, direct_target)."""
    e = "<" if endian == "little" else ">"
    if arch == "x86_64":
        if len(code) >= 5 and code[-5] == 0xE8:
            rel = struct.unpack_from(e + "i", code, len(code) - 4)[0]
            return CALL_DIRECT, (ra + rel) & 0xFFFFFFFFFFFFFFFF
        for ln in (2, 3, 4, 6, 7, 8):
            if len(code) < ln:
                break
            i = len(code) - ln
            if 0x40 <= code[i] <= 0x4F:
                i += 1
            if i >= len(code) or code[i] != 0xFF:
                continue
            if i + 1 >= len(code) or ((code[i + 1] >> 3) & 7) != 2:
                continue
            ml = _x86_modrm_len(code, i + 1)
            if ml is not None and i + 1 + ml == len(code):
                return CALL_INDIRECT, None
        return None, None
    if arch == "aarch64":
        if len(code) < 4:
            return None, None
        insn = struct.unpack_from(e + "I", code, len(code) - 4)[0]
        if (insn >> 26) == 0x25:  # BL imm26
            imm = insn & 0x03FFFFFF
            if imm & 0x02000000:
                imm -= 1 << 26
            return CALL_DIRECT, (ra - 4 + imm * 4) & 0xFFFFFFFFFFFFFFFF
        if (insn & 0xFFFFFC1F) == 0xD63F0000:  # BLR Xn
            return CALL_INDIRECT, None
        if (insn & 0xFFFFF800) in (0xD63F0800, 0xD73F0800):  # BLRAA[Z] / BLRAB[Z]
            return CALL_INDIRECT, None
        return None, None
    return None, None


# --------------------------------------------------------------------------------------
# Process view: modules from /proc/PID/maps and a budgeted stack reader
# --------------------------------------------------------------------------------------
@dataclass
class Module:
    path: str
    name: str
    image: Optional[ElfImage]
    bias: int
    exec_ranges: List[Tuple[int, int]]


class StackReader:
    """Page-granular cache over the caller's non-stopping ``read_memory``, bounded to one region."""

    PAGE = 4096

    def __init__(self, read_memory: Callable[[int, int], Tuple[Optional[bytes], str, Optional[str]]],
                 lo: int, hi: int, ptr_size: int, endian: str, max_bytes: int = 256 * 1024):
        self._read = read_memory
        self.lo = lo
        self.hi = hi
        self.ptr_size = ptr_size
        self._fmt = ("<" if endian == "little" else ">") + ("Q" if ptr_size == 8 else "I")
        self._pages: Dict[int, Optional[bytes]] = {}
        self.reads = 0
        self.bytes = 0
        self.max_bytes = max_bytes
        self.errors: List[str] = []
        self.budget_exhausted = False

    def _page(self, base: int) -> Optional[bytes]:
        if base in self._pages:
            return self._pages[base]
        if self.bytes + self.PAGE > self.max_bytes:
            self.budget_exhausted = True
            return None
        start = max(base, self.lo)
        end = min(base + self.PAGE, self.hi)
        data: Optional[bytes] = None
        if end > start:
            try:
                raw, st, err = self._read(start, end - start)
            except Exception as exc:  # noqa: BLE001
                raw, st, err = None, "READ_ERROR", f"{type(exc).__name__}: {exc}"
            self.reads += 1
            if st == "OBSERVED" and raw:
                self.bytes += len(raw)
                data = (b"\x00" * (start - base)) + raw
            else:
                self.errors.append(f"stack read 0x{start:x}+{end - start} failed: {err or st}")
        self._pages[base] = data
        return data

    def word(self, addr: int) -> Optional[int]:
        if addr < self.lo or addr + self.ptr_size > self.hi or addr % self.ptr_size:
            return None
        base = addr & ~(self.PAGE - 1)
        page = self._page(base)
        if page is None or (addr - base) + self.ptr_size > len(page):
            return None
        return struct.unpack_from(self._fmt, page, addr - base)[0]

    def snapshot(self, lo: int, hi: int) -> Dict[int, int]:
        out: Dict[int, int] = {}
        a = (max(lo, self.lo) + self.ptr_size - 1) & ~(self.ptr_size - 1)
        while a + self.ptr_size <= min(hi, self.hi):
            w = self.word(a)
            if w is not None:
                out[a] = w
            a += self.ptr_size
        return out


@dataclass
class _State:
    pc: int
    sp: Optional[int]
    regs: Dict[int, int]
    exact_pc: bool          # frame 0 / signal-interrupted frame: look up rows at pc, not pc-1
    method: str
    estimated: bool
    extra: Dict[str, Any] = field(default_factory=dict)


class CfiUnwinder:
    """Unwinds threads of one process.  ``mappings`` are /proc/PID/maps entries (dicts with
    start_int, end_int, permissions, offset_int, pathname); ``read_memory(addr, size)`` must be
    the zero-stop, budget-accounted target read path."""

    def __init__(self, arch: str, mappings: Sequence[Dict[str, Any]],
                 read_memory: Callable[[int, int], Tuple[Optional[bytes], str, Optional[str]]],
                 endian: str = "little", file_resolver: Optional[Callable[[str], Optional[str]]] = None,
                 extra_images: Optional[Dict[str, str]] = None,
                 max_stack_bytes: int = 256 * 1024, scan_window: int = 64 * 1024):
        if arch not in ARCH_SPECS:
            raise ValueError(f"CFI unwinding is not implemented for architecture {arch!r}")
        self.arch = ARCH_SPECS[arch]
        self.endian = endian
        self._read = read_memory
        self._mappings = [m for m in mappings if m.get("end_int", 0) > m.get("start_int", 0)]
        self._file_resolver = file_resolver
        self._extra_images = dict(extra_images or {})
        self.max_stack_bytes = max_stack_bytes
        self.scan_window = scan_window
        self._modules: Dict[str, Optional[Module]] = {}
        self._exec_index: List[Tuple[int, int, str]] = sorted(
            (int(m["start_int"]), int(m["end_int"]), m.get("pathname") or "")
            for m in self._mappings if "x" in (m.get("permissions") or "")
        )
        self._exec_starts = [r[0] for r in self._exec_index]
        max_end = max((int(m["end_int"]) for m in self._mappings), default=1 << 47)
        va_bits = max(39, (max_end - 1).bit_length())
        self._addr_mask = (1 << va_bits) - 1 if arch == "aarch64" else (1 << 64) - 1
        self.va_bits = va_bits
        self._plt_cache: Dict[int, Optional[int]] = {}
        self.aux_reads = 0   # GOT reads for PLT resolution (outside the stack reader)
        self.aux_bytes = 0

    # -- modules -------------------------------------------------------------------------
    def _exec_path(self, addr: int) -> Optional[str]:
        i = bisect.bisect_right(self._exec_starts, addr) - 1
        if i >= 0:
            s, e, p = self._exec_index[i]
            if s <= addr < e:
                return p
        return None

    def in_code(self, addr: int) -> bool:
        return self._exec_path(addr) is not None

    def module_for(self, addr: int) -> Optional[Module]:
        path = self._exec_path(addr)
        if path is None:
            return None
        if path in self._modules:
            return self._modules[path]
        mod: Optional[Module] = None
        img: Optional[ElfImage] = None
        if path.startswith("/"):
            local = self._extra_images.get(path) or path
            if self._file_resolver is not None:
                local = self._file_resolver(path) or local
            img = load_elf_image(local)
            if img is not None and img.arch != self.arch.name:
                img = None
        bias = 0
        ranges = [(int(m["start_int"]), int(m["end_int"])) for m in self._mappings
                  if (m.get("pathname") or "") == path and "x" in (m.get("permissions") or "")]
        if img is not None:
            b = None
            for m in self._mappings:
                if (m.get("pathname") or "") != path:
                    continue
                off = m.get("offset_int")
                if off is None:
                    try:
                        off = int(str(m.get("offset", "0")), 16)
                    except ValueError:
                        off = 0
                b = img.load_bias_for_mapping(int(m["start_int"]), int(off))
                if b is not None:
                    break
            bias = b if b is not None else 0
            if img.e_type == 2:  # ET_EXEC
                bias = 0
        mod = Module(path, os.path.basename(path) or path, img, bias, ranges)
        self._modules[path] = mod
        return mod

    def describe_pc(self, pc: int, lookup_pc: int) -> Dict[str, Any]:
        """Module / ELF-symbol information for a frame PC (independent of DWARF)."""
        mod = self.module_for(lookup_pc)
        out: Dict[str, Any] = {"module": None, "module_path": None, "link_pc": None, "elf_symbol": None,
                               "elf_symbol_start": None}
        if mod is None:
            return out
        out["module"] = mod.name
        out["module_path"] = mod.path
        lt = lookup_pc - mod.bias
        out["link_pc"] = lt
        if mod.image is not None:
            sym = mod.image.symbolize(lt)
            if sym is not None:
                out["elf_symbol"] = sym[0]
                out["elf_symbol_start"] = sym[1] + mod.bias
        return out

    def function_start(self, addr: int) -> Optional[int]:
        mod = self.module_for(addr)
        if mod is None or mod.image is None:
            return None
        lt = addr - mod.bias
        fde = mod.image.find_fde(lt)
        if fde is not None:
            return fde.pc_begin + mod.bias
        sym = mod.image.symbolize(lt)
        return (sym[1] + mod.bias) if sym else None

    def code_before(self, addr: int, n: int) -> Optional[bytes]:
        mod = self.module_for(addr - 1)
        if mod is None or mod.image is None:
            return None
        return mod.image.read_vaddr(addr - n - mod.bias, n)

    def call_site(self, ra: int) -> Tuple[Optional[str], Optional[int]]:
        """Kind of the call instruction ending at ``ra`` and its direct target.  A direct call into a
        PLT stub is resolved through the GOT (one accounted target read); unresolvable -> indirect."""
        n = 8 if self.arch.name == "x86_64" else 4
        code = self.code_before(ra, n)
        if code is None:
            return None, None
        kind, target = decode_call_before(self.arch.name, code, ra, self.endian)
        if kind == CALL_DIRECT and target is not None and self.is_plt_target(target):
            real = self._resolve_plt(target)
            return (CALL_DIRECT, real) if real is not None else (CALL_INDIRECT, None)
        return kind, target

    def _resolve_plt(self, stub: int) -> Optional[int]:
        if stub in self._plt_cache:
            return self._plt_cache[stub]
        self._plt_cache[stub] = None
        mod = self.module_for(stub)
        if mod is None or mod.image is None:
            return None
        lt = stub - mod.bias
        code = mod.image.read_vaddr(lt, 24)
        if not code:
            return None
        e = "<" if self.endian == "little" else ">"
        got_link: Optional[int] = None
        if self.arch.name == "x86_64":
            i = code.find(b"\xff\x25")
            if 0 <= i <= 12:
                got_link = lt + i + 6 + struct.unpack_from(e + "i", code, i + 2)[0]
        elif self.arch.name == "aarch64":
            j = 4 if struct.unpack_from(e + "I", code, 0)[0] == 0xD503245F else 0  # optional `bti c`
            adrp, ldr = struct.unpack_from(e + "II", code, j)
            if (adrp & 0x9F00001F) == 0x90000010 and (ldr & 0xFFC003FF) == 0xF9400211:
                imm = (((adrp >> 5) & 0x7FFFF) << 2) | ((adrp >> 29) & 3)
                if imm & (1 << 20):
                    imm -= 1 << 21
                page = ((lt + j) & ~0xFFF) + (imm << 12)
                got_link = page + ((ldr >> 10) & 0xFFF) * 8
        if got_link is None:
            return None
        try:
            raw, st, _err = self._read(got_link + mod.bias, self.arch.ptr_size)
        except Exception:  # noqa: BLE001
            raw, st = None, "READ_ERROR"
        self.aux_reads += 1
        if st != "OBSERVED" or not raw or len(raw) < self.arch.ptr_size:
            return None
        self.aux_bytes += len(raw)
        val = self.strip_ra(struct.unpack_from(e + ("Q" if self.arch.ptr_size == 8 else "I"), raw, 0)[0])
        if not self.in_code(val) or self.is_plt_target(val):
            return None  # lazy binding not done yet / garbage
        self._plt_cache[stub] = val
        return val

    def is_plt_target(self, addr: int) -> bool:
        mod = self.module_for(addr)
        return bool(mod and mod.image and mod.image.is_plt(addr - mod.bias))

    def strip_ra(self, ra: int) -> int:
        return ra & self._addr_mask

    # -- reading -------------------------------------------------------------------------
    def stack_bounds(self, sp: int) -> Tuple[int, int]:
        for m in self._mappings:
            if int(m["start_int"]) <= sp < int(m["end_int"]):
                return int(m["start_int"]), int(m["end_int"])
        return sp, sp + 4096

    def _row(self, pc: int, exact_pc: bool) -> Tuple[Optional[Module], Optional[Fde], Optional[CfiRow], Optional[str]]:
        lookup = pc if exact_pc else pc - 1
        mod = self.module_for(lookup)
        if mod is None:
            return None, None, None, "pc_not_in_mapped_code"
        if mod.image is None:
            return mod, None, None, "module_image_unavailable"
        lt = lookup - mod.bias
        try:
            res = mod.image.row_at(lt)
        except Exception as exc:  # noqa: BLE001
            return mod, None, None, f"cfi_program_error: {exc}"
        if res is None:
            return mod, None, None, "no_fde"
        return mod, res[0], res[1], None

    # -- one CFI step -------------------------------------------------------------------
    def _apply_row(self, st: _State, row: CfiRow, cfa: int, rd: StackReader) -> Tuple[Optional[Dict[int, int]], Optional[str], Optional[int], bool]:
        """Compute the caller's registers. Returns (caller_regs, stop_reason, ra, ra_undefined)."""
        A = self.arch
        new: Dict[int, int] = {}
        for reg in A.callee_saved:
            if reg in st.regs:
                new[reg] = st.regs[reg]
        unknown_rules: List[int] = []
        for reg, (kind, val) in row.rules.items():
            if kind == R_OFFSET:
                w = rd.word(cfa + val)
                if w is None:
                    new.pop(reg, None)
                    if reg == A.ra_reg:
                        return None, f"saved_return_address_unreadable@0x{cfa + val:x}", None, False
                    continue
                new[reg] = w
            elif kind == R_VAL_OFFSET:
                new[reg] = cfa + val
            elif kind == R_REGISTER:
                if val in st.regs:
                    new[reg] = st.regs[val]
                else:
                    new.pop(reg, None)
            elif kind == R_SAME:
                if reg in st.regs:
                    new[reg] = st.regs[reg]
            elif kind == R_UNDEFINED:
                new.pop(reg, None)
            else:  # expression / val_expression: not evaluated -> unknown value
                new.pop(reg, None)
                unknown_rules.append(reg)
        ra_rule = row.rules.get(A.ra_reg)
        if ra_rule is not None and ra_rule[0] == R_UNDEFINED:
            return new, STOP_OUTERMOST, None, True
        if A.ra_reg in unknown_rules:
            return None, "return_address_rule_is_expression", None, False
        if ra_rule is None or ra_rule[0] == R_SAME:
            # aarch64: the RA is still in x30, whose value is not published for a live thread
            # (only SP/PC are).  x30 is never propagated across frames (a call clobbers it).
            return None, "return_address_in_register_unknown", None, False
        ra = new.pop(A.ra_reg, None)
        if ra is None:
            return None, "return_address_unknown", None, False
        return new, None, ra, False

    # -- unwinding a blocked thread ------------------------------------------------------
    def unwind_blocked(self, sp: int, pc: int, max_frames: int = 64) -> Dict[str, Any]:
        """Unwind from kernel-reported SP/PC of a thread blocked in a syscall."""
        t0 = time.monotonic_ns()
        lo, hi = self.stack_bounds(sp)
        rd = StackReader(self._read, lo, hi, self.arch.ptr_size, self.endian, self.max_stack_bytes)
        frames: List[Dict[str, Any]] = []
        notes: List[str] = []
        st = _State(pc=pc, sp=sp, regs={self.arch.sp_reg: sp}, exact_pc=True,
                    method=UNWIND_REGISTERS, estimated=False)
        a0, b0 = self.aux_reads, self.aux_bytes
        stop = self._walk(st, rd, frames, notes, max_frames)
        return self._result(frames, stop, notes, rd, t0, extra_reads=self.aux_reads - a0,
                            extra_bytes=self.aux_bytes - b0)

    def _result(self, frames: List[Dict[str, Any]], stop: str, notes: List[str], rd: StackReader, t0: int,
                running: bool = False, extra_reads: int = 0, extra_bytes: int = 0) -> Dict[str, Any]:
        any_est = any(f["estimated"] for f in frames)
        if running:
            status = STATUS_RUNNING_SAMPLE
        elif any_est:
            status = STATUS_PARTIAL_ESTIMATED
        elif stop == STOP_OUTERMOST:
            status = STATUS_COMPLETE
        else:
            status = STATUS_TRUNCATED
        return {
            "status": status,
            "frames": frames,
            "stop_reason": stop,
            "notes": notes,
            "arch": self.arch.name,
            "cost": {
                "target_reads": rd.reads + extra_reads,
                "target_bytes": rd.bytes + extra_bytes,
                "elapsed_us": round((time.monotonic_ns() - t0) / 1000.0, 1),
                "budget_exhausted": rd.budget_exhausted,
            },
            "read_errors": list(rd.errors[:5]),
        }

    def _emit(self, frames: List[Dict[str, Any]], st: _State, cfa: Optional[int], fde: Optional[Fde],
              mod: Optional[Module], row: Optional[CfiRow]) -> Dict[str, Any]:
        f = {
            "index": len(frames),
            "pc": st.pc,
            "lookup_pc": st.pc if st.exact_pc else st.pc - 1,
            "sp": st.sp,
            "cfa": cfa,
            "regs": dict(st.regs),
            "unwind": st.method,
            "estimated": st.estimated,
            "fde_start": (fde.pc_begin + mod.bias) if (fde is not None and mod is not None) else None,
            "cfi_source": fde.source if fde is not None else None,
            "pac_signed_ra": bool(row.ra_signed) if row is not None else False,
        }
        f.update(st.extra)
        frames.append(f)
        return f

    def _walk(self, st: _State, rd: StackReader, frames: List[Dict[str, Any]], notes: List[str],
              max_frames: int) -> str:
        """Main loop: CFI, frame-pointer and scan tiers until the outermost frame / budget."""
        A = self.arch
        seen: set = set()
        while len(frames) < max_frames:
            if rd.budget_exhausted:
                return "read_budget_exhausted"
            key = (st.pc, st.sp, st.regs.get(A.fp_reg))
            if key in seen:
                return "unwind_loop_detected"
            seen.add(key)
            mod, fde, row, why = self._row(st.pc, st.exact_pc)
            cfa: Optional[int] = None
            if row is not None and row.cfa_expr is None and not row.unsupported:
                base = st.regs.get(row.cfa_reg) if row.cfa_reg is not None else None
                if base is None and row.cfa_reg == A.sp_reg and st.sp is not None:
                    base = st.sp
                if base is not None:
                    cfa = (base + row.cfa_offset) & ((1 << 64) - 1)
                elif row.cfa_reg == A.fp_reg:
                    inferred = self._infer_frame_pointer(st, row, fde, mod, rd)
                    if inferred is not None:
                        st.regs[A.fp_reg] = inferred[0]
                        st.extra["fp_inferred"] = True
                        st.extra["fp_inference"] = inferred[1]
                        cfa = (inferred[0] + row.cfa_offset) & ((1 << 64) - 1)
                        notes.append(f"frame {len(frames)}: {A.reg_names.get(A.fp_reg)} inferred from a "
                                     f"call-site-validated frame record ({inferred[1]})")
                    else:
                        why = f"cfa_register_unknown:{A.reg_names.get(row.cfa_reg, row.cfa_reg)}"
                else:
                    why = f"cfa_register_unknown:{A.reg_names.get(row.cfa_reg, row.cfa_reg)}"
            elif row is not None:
                why = "cfa_expression" if row.cfa_expr is not None else f"unsupported_cfi:{','.join(row.unsupported)}"

            if cfa is not None:
                fr = self._emit(frames, st, cfa, fde, mod, row)
                fp_inferred_here = bool(st.extra.get("fp_inferred"))
                if fp_inferred_here:
                    fr["cfa_source"] = "inferred_frame_pointer"
                new_regs, stop, ra, _undef = self._apply_row(st, row, cfa, rd)  # type: ignore[arg-type]
                if stop == STOP_OUTERMOST:
                    return STOP_OUTERMOST
                if stop is None and ra is not None:
                    ra_s = self.strip_ra(ra)
                    if ra_s != ra:
                        fr["pac_stripped"] = True
                    if ra_s == 0:
                        return STOP_OUTERMOST
                    if st.sp is not None and cfa < st.sp:
                        return "cfa_below_stack_pointer"
                    if not self.in_code(ra_s):
                        return f"return_address_not_in_code:0x{ra_s:x}"
                    new_regs[A.sp_reg] = cfa  # type: ignore[index]
                    if st.estimated:
                        nmethod = UNWIND_CFI_AFTER_SCAN
                    elif fp_inferred_here:
                        nmethod = UNWIND_FRAME_POINTER
                    else:
                        nmethod = UNWIND_CFI
                    st = _State(pc=ra_s, sp=cfa, regs=new_regs, exact_pc=False,  # type: ignore[arg-type]
                                method=nmethod, estimated=st.estimated)
                    continue
                # CFA known but RA not recoverable: continue below with a scan from the CFA
                why = stop
                frames.pop()
                return self._fallback(st, cfa, mod, fde, row, rd, frames, notes, max_frames, why or "unknown")
            return self._fallback(st, None, mod, fde, row, rd, frames, notes, max_frames, why or "unknown")
        return "max_frames"

    # -- frame pointer inference (CFA = fp + off, fp unknown) ----------------------------
    def _infer_frame_pointer(self, st: _State, row: CfiRow, fde: Optional[Fde], mod: Optional[Module],
                             rd: StackReader) -> Optional[Tuple[int, str]]:
        A = self.arch
        ra_rule = row.rules.get(A.ra_reg)
        if st.sp is None or ra_rule is None or ra_rule[0] != R_OFFSET or fde is None or mod is None:
            return None
        fp_rule = row.rules.get(A.fp_reg)
        func_start = fde.pc_begin + mod.bias
        p = A.ptr_size
        best_indirect: Optional[Tuple[int, str]] = None
        start = (st.sp + p - 1) & ~(p - 1)
        for cand in range(start, min(st.sp + self.scan_window, rd.hi), p):
            cfa = cand + row.cfa_offset
            if cfa <= st.sp:
                continue
            ra = rd.word(cfa + ra_rule[1])
            if ra is None:
                if rd.budget_exhausted:
                    break
                continue
            ra = self.strip_ra(ra)
            if not self.in_code(ra):
                continue
            if fp_rule is not None and fp_rule[0] == R_OFFSET:
                saved_fp = rd.word(cfa + fp_rule[1])
                if saved_fp is None or not (saved_fp == 0 or saved_fp > cand):
                    continue
            kind, target = self.call_site(ra)
            if kind == CALL_DIRECT:
                if target == func_start:
                    return cand, "direct_call_to_this_function"
                if self.is_plt_target(target or 0) and best_indirect is None:
                    best_indirect = (cand, "call_through_plt")
            elif kind == CALL_INDIRECT and best_indirect is None:
                best_indirect = (cand, "indirect_call")
        return best_indirect

    # -- fallbacks -------------------------------------------------------------------------
    def _fallback(self, st: _State, cfa: Optional[int], mod: Optional[Module], fde: Optional[Fde],
                  row: Optional[CfiRow], rd: StackReader, frames: List[Dict[str, Any]], notes: List[str],
                  max_frames: int, why: str) -> str:
        A = self.arch
        p = A.ptr_size
        notes.append(f"frame {len(frames)} (pc 0x{st.pc:x}): CFI cannot continue ({why})")
        # (1) frame record walk when no FDE but the frame pointer value is known
        fp = st.regs.get(A.fp_reg)
        if fde is None and fp is not None and (st.sp is None or fp >= st.sp) and rd.lo <= fp < rd.hi:
            prev_fp = rd.word(fp)
            ra = rd.word(fp + p)
            if ra is not None and prev_fp is not None:
                ra = self.strip_ra(ra)
                func_start = self.function_start(st.pc if st.exact_pc else st.pc - 1)
                kind, target = self.call_site(ra) if self.in_code(ra) else (None, None)
                ok = kind == CALL_INDIRECT or (kind == CALL_DIRECT and (func_start is None or target == func_start
                                                                         or self.is_plt_target(target or 0)))
                if ok and (prev_fp == 0 or prev_fp > fp):
                    fcfa = fp + 2 * p if A.name == "x86_64" else None
                    fr = self._emit(frames, st, fcfa, None, mod, None)
                    fr["cfa_source"] = "frame_record" if fcfa is not None else None
                    regs = {r: v for r, v in st.regs.items() if r in A.callee_saved}
                    regs[A.fp_reg] = prev_fp
                    new_sp = fp + 2 * p if A.name == "x86_64" else None
                    if new_sp is not None:
                        regs[A.sp_reg] = new_sp
                    if prev_fp == 0 and A.name == "aarch64" and not self.in_code(ra):
                        return STOP_OUTERMOST
                    nst = _State(pc=ra, sp=new_sp, regs=regs, exact_pc=False,
                                 method=UNWIND_FRAME_POINTER, estimated=st.estimated)
                    return self._walk(nst, rd, frames, notes, max_frames)
        # (2) aarch64 frames whose CFA is sp-based but sp is unknown after a frame-record step
        if row is not None and fde is not None and st.sp is None and fp is not None and A.name == "aarch64":
            fp_rule = row.rules.get(A.fp_reg)
            ra_rule = row.rules.get(A.ra_reg)
            if fp_rule and ra_rule and fp_rule[0] == R_OFFSET and ra_rule[0] == R_OFFSET \
                    and ra_rule[1] == fp_rule[1] + p:
                fcfa = fp - fp_rule[1]  # frame record convention: x29 points at its own save slot
                ra = rd.word(fcfa + ra_rule[1])
                prev_fp = rd.word(fcfa + fp_rule[1])
                if ra is not None and prev_fp is not None:
                    ra = self.strip_ra(ra)
                    kind, target = self.call_site(ra) if self.in_code(ra) else (None, None)
                    func_start = fde.pc_begin + (mod.bias if mod else 0)
                    if kind == CALL_INDIRECT or (kind == CALL_DIRECT and (target == func_start or self.is_plt_target(target or 0))):
                        st.sp = fcfa - row.cfa_offset if row.cfa_reg == A.sp_reg else None
                        fr = self._emit(frames, st, fcfa, fde, mod, row)
                        fr["cfa_source"] = "frame_record"
                        new_regs, stop, ra2, _u = self._apply_row(st, row, fcfa, rd)
                        if stop == STOP_OUTERMOST:
                            return STOP_OUTERMOST
                        if new_regs is not None and ra2 is not None and self.in_code(self.strip_ra(ra2)):
                            new_regs[A.sp_reg] = fcfa
                            nst = _State(pc=self.strip_ra(ra2), sp=fcfa, regs=new_regs, exact_pc=False,
                                         method=UNWIND_FRAME_POINTER, estimated=st.estimated)
                            return self._walk(nst, rd, frames, notes, max_frames)
                        frames.pop()
        # (3) stack scan, call-site validated, with CFI resumption from the anchor when possible
        return self._scan(st, cfa, rd, frames, notes, max_frames, why)

    def _callee_ra_offsets(self, func_start: int) -> Tuple[Optional[Module], Optional[Fde], List[Tuple[int, CfiRow]]]:
        """For function starting at ``func_start``: rows (in its body) where the RA is saved,
        as [(offset of saved RA relative to CFA, row)]."""
        mod = self.module_for(func_start)
        if mod is None or mod.image is None:
            return mod, None, []
        fde = mod.image.find_fde(func_start - mod.bias)
        if fde is None or fde.pc_begin + mod.bias != func_start:
            return mod, fde if fde is not None else None, []
        out: List[Tuple[int, CfiRow]] = []
        try:
            rows = mod.image.all_rows(fde)
        except Exception:  # noqa: BLE001
            return mod, fde, []
        for i, r in enumerate(rows):
            rule = r.rules.get(self.arch.ra_reg)
            if rule is not None and rule[0] == R_OFFSET:
                # remember how long this row is in effect (used to pick the function's body row)
                r.span = (rows[i + 1].loc if i + 1 < len(rows) else fde.pc_end) - r.loc  # type: ignore[attr-defined]
                out.append((rule[1], r))
        return mod, fde, out

    def _anchor_from_slot(self, slot: int, callee_start: Optional[int], rd: StackReader) -> Optional[Tuple[int, Dict[int, int]]]:
        """Given the stack slot holding the callee's saved return address, return
        (callee CFA, callee-saved registers restored from the callee's frame)."""
        A = self.arch
        if A.name == "x86_64" and callee_start is None:
            return slot + A.ptr_size, {}
        if callee_start is None:
            return None
        _mod, _fde, offs = self._callee_ra_offsets(callee_start)
        ks = {k for k, _r in offs}
        if len(ks) != 1:
            if A.name == "x86_64":
                return slot + A.ptr_size, {}
            return None
        k = next(iter(ks))
        cfa = slot - k
        regs: Dict[int, int] = {}
        # callee-saved registers saved in the callee's body rows at a consistent offset
        cand: Dict[int, set] = {}
        for _k, r in offs:
            for reg, (kind, val) in r.rules.items():
                if reg in A.callee_saved and kind == R_OFFSET:
                    cand.setdefault(reg, set()).add(val)
        for reg, vals in cand.items():
            if len(vals) == 1 and all(reg in r.rules for _k, r in offs):
                w = rd.word(cfa + next(iter(vals)))
                if w is not None:
                    regs[reg] = w
        return cfa, regs

    def _next_scan_candidate(self, a: int, scan_hi: int, rd: StackReader, expect: Optional[int],
                             any_call: bool) -> Optional[Tuple[int, int, str, Optional[int]]]:
        """Next stack slot (>= a) holding a return address for the frame of function ``expect``.

        A direct call to ``expect`` wins; a direct call to any other function is a stale return
        address and is skipped; an indirect call (function pointer / unresolved PLT) is only taken
        when no direct match exists in the window.  ``any_call``: caller identity unknown - the first
        call-preceded return address is taken."""
        p = self.arch.ptr_size
        first_indirect: Optional[Tuple[int, int, str, Optional[int]]] = None
        while a + p <= scan_hi:
            w = rd.word(a)
            if w is None:
                if rd.budget_exhausted:
                    break
                a += p
                continue
            ra = self.strip_ra(w)
            if self.in_code(ra) and self.function_start(ra) != ra:
                kind, target = self.call_site(ra)
                if kind is not None:
                    if any_call or expect is None:
                        return a, ra, kind, target
                    if kind == CALL_DIRECT and target == expect:
                        return a, ra, kind, target
                    if kind == CALL_INDIRECT and first_indirect is None:
                        first_indirect = (a, ra, kind, target)
            a += p
        return first_indirect

    def _scan(self, st: _State, cfa: Optional[int], rd: StackReader, frames: List[Dict[str, Any]],
              notes: List[str], max_frames: int, why: str) -> str:
        A = self.arch
        p = A.ptr_size
        # The current frame itself is emitted (it is real: its PC is known), then its callers are scanned.
        expect = self.function_start(st.pc if st.exact_pc else st.pc - 1)
        gap_callee_unknown = why in ("return_address_in_register_unknown",)
        fr = self._emit(frames, st, cfa, None, None, None)
        fr["unwind_stop_reason"] = why
        start = cfa if cfa is not None else (st.sp if st.sp is not None else st.regs.get(A.fp_reg))
        if start is None:
            return f"scan_impossible:{why}"
        scan_lo = (start + p - 1) & ~(p - 1)
        scan_hi = min(scan_lo + self.scan_window, rd.hi)
        a = scan_lo
        while len(frames) < max_frames:
            cand = self._next_scan_candidate(a, scan_hi, rd, expect, gap_callee_unknown)
            if cand is None:
                if rd.budget_exhausted:
                    return "read_budget_exhausted"
                break
            a, ra, kind, target = cand
            if gap_callee_unknown and kind == CALL_DIRECT and target is not None and target != expect:
                # aarch64 leaf with RA in x30: the caller's identity is recovered from the call target
                gst = _State(pc=target, sp=cfa, regs={}, exact_pc=True, method=UNWIND_SCAN, estimated=True,
                             extra={"pc_is_function_entry": True, "unwound_via": "CALL_TARGET_OF_SCANNED_RETURN_ADDRESS"})
                self._emit(frames, gst, None, None, None, None)
                expect = target
            gap_callee_unknown = False
            # anchor: the callee of the frame that `ra` returns into is `expect` (when known)
            anchor = self._anchor_from_slot(a, target if kind == CALL_DIRECT else expect, rd)
            if anchor is not None and (st.sp is None or anchor[0] > st.sp):
                ccfa, cregs = anchor
                if frames and frames[-1].get("cfa") is None:
                    frames[-1]["cfa"] = ccfa
                    frames[-1]["cfa_source"] = "scan_anchor"
                cregs[A.sp_reg] = ccfa
                nst = _State(pc=ra, sp=ccfa, regs=cregs, exact_pc=False, method=UNWIND_SCAN, estimated=True,
                             extra={"stack_slot": a})
                return self._walk(nst, rd, frames, notes, max_frames)
            nst = _State(pc=ra, sp=None, regs={}, exact_pc=False, method=UNWIND_SCAN, estimated=True,
                         extra={"stack_slot": a})
            self._emit(frames, nst, None, None, None, None)
            expect = self.function_start(ra - 1)
            a += p
        return f"scan_exhausted:{why}" if len(frames) < max_frames else "max_frames"

    # -- running threads -----------------------------------------------------------------
    def sample_running(self, lo: int, hi: int, max_frames: int = 64, settle_s: float = 0.002) -> Dict[str, Any]:
        """Best effort for a thread running on a CPU (no SP/PC available).

        The stack window is read twice (``settle_s`` apart).  Words that changed between the reads
        belong to the innermost live frame (a caller's frame is not written while its callee runs),
        which separates live frames from stale return addresses left by earlier, deeper calls.
        Each read is unwound (anchors + CFI, see :meth:`_running_once`); the frames are always
        labelled ``running_sample_estimated`` and ``sample_stable`` says whether both reads agreed."""
        t0 = time.monotonic_ns()
        a0, b0 = self.aux_reads, self.aux_bytes
        readers: List[StackReader] = []
        snaps: List[Dict[int, int]] = []
        for i in range(2):
            rd = StackReader(self._read, lo, hi, self.arch.ptr_size, self.endian, self.max_stack_bytes)
            snaps.append(rd.snapshot(lo, hi))
            readers.append(rd)
            if i == 0 and settle_s > 0:
                time.sleep(settle_s)
        changed = sorted(a for a, v in snaps[1].items() if snaps[0].get(a, v) != v)
        results = [self._running_once(rd, lo, hi, max_frames, changed) for rd in readers]
        f1, _s1, _n1 = results[0]
        f2, stop2, notes2 = results[1]
        rd2 = readers[1]
        sig1 = [(f["pc"], f.get("cfa")) for f in f1]
        sig2 = [(f["pc"], f.get("cfa")) for f in f2]
        stable = sig1 == sig2 and bool(f2)
        for f in f2:
            f["unwind"] = UNWIND_RUNNING
            f["estimated"] = True
            f["sample_stable"] = stable
        notes2 = list(notes2) + [
            "thread was running on a CPU: no kernel-reported SP/PC; frames are a two-read stack sample "
            f"({'both reads agreed' if stable else 'the two reads disagreed'}; "
            f"{len(changed)} stack word(s) changed between the reads)"
        ]
        res = self._result(f2, stop2, notes2, rd2, t0, running=True,
                           extra_reads=readers[0].reads + self.aux_reads - a0,
                           extra_bytes=readers[0].bytes + self.aux_bytes - b0)
        res["sample_stable"] = stable
        res["changed_stack_words"] = len(changed)
        return res

    def _running_once(self, rd: StackReader, lo: int, hi: int, max_frames: int,
                      changed: Sequence[int] = ()) -> Tuple[List[Dict[str, Any]], str, List[str]]:
        A = self.arch
        p = A.ptr_size
        notes: List[str] = []
        # 1. anchors: every call-site-validated stack slot (a return address whose callee's CFI places
        #    it exactly there) is unwound with CFI; chains that reach the outermost frame are kept.
        #    Stale return addresses left below the live stack pointer by earlier, deeper calls also
        #    produce such chains (they merge into the live frames further up).  The window is walked
        #    from its top (live frames sit near the top of a thread stack) with a bounded number of tries.
        chains: List[List[Dict[str, Any]]] = []
        marked: List[bool] = []
        a = (hi - p) & ~(p - 1)
        lo_al = (lo + p - 1) & ~(p - 1)
        tries = 0
        while a >= lo_al and tries < 256:
            w = rd.word(a)
            if w is None:
                if rd.budget_exhausted:
                    break
                a -= p
                continue
            ra = self.strip_ra(w)
            if not self.in_code(ra) or self.function_start(ra) == ra:
                a -= p
                continue
            kind, target = self.call_site(ra)
            if kind is None:
                a -= p
                continue
            callee = target if kind == CALL_DIRECT else None
            anchor = self._anchor_from_slot(a, callee, rd)
            if anchor is None:
                a -= p
                continue
            tries += 1
            ccfa, cregs = anchor
            fr: List[Dict[str, Any]] = []
            if callee is not None:
                fr.append(self._entry_frame(callee, ccfa, cregs, a))
            regs = dict(cregs)
            regs[A.sp_reg] = ccfa
            st = _State(pc=ra, sp=ccfa, regs=regs, exact_pc=False, method=UNWIND_RUNNING, estimated=True)
            stop = self._walk_cfi_only(st, rd, fr, max_frames)
            if stop in (STOP_OUTERMOST, _OUTERMOST_ZERO_RA) and fr:
                chains.append(fr)
                marked.append(stop == STOP_OUTERMOST)
            a -= p
        if not chains:
            return [], "no_consistent_anchor_in_stack_sample", notes
        # chains ending at an explicit outermost marker (CFI "RA undefined": _start, thread_start,
        # clone) are preferred over chains that merely read a zero return address
        if any(marked):
            chains = [c for c, mk in zip(chains, marked) if mk]
        # 2. top-down merge: the outermost frame is live; at each level the candidate callees are the
        #    chains' frames below it plus the directly verified callee (`_callee_of`); the one whose
        #    saved return address is topmost (closest to the caller's frame) is taken - a live callee
        #    overwrites the region it uses, stale frames survive mostly below it.
        #    Choice per level, strongest evidence first:
        #      (1) activity: stack words that changed between the two reads are written by the running
        #          innermost frame or, when its callee returns often, by its immediate caller.  An option
        #          whose chain would put a changed word two or more frames above its innermost frame
        #          is rejected (unless that rejects every option);
        #      (2) the latest call site in the caller (setup calls precede the long-running one);
        #      (3) the topmost saved return address.
        top_cfa = max(c[-1]["cfa"] for c in chains)
        chains = [c for c in chains if c[-1]["cfa"] == top_cfa]
        cur = dict(chains[0][-1])
        refined: List[Dict[str, Any]] = [cur]
        ambiguous = 0

        def activity_depth(below: List[Dict[str, Any]], level_sp: int) -> int:
            """Deepest position (0 = innermost frame) at which a changed word below this level falls."""
            cfas = sorted(f["cfa"] for f in below if f.get("cfa") is not None)
            return max((bisect.bisect_right(cfas, w) for w in changed if w < level_sp), default=0)

        while len(refined) < max_frames:
            # (ra slot, caller pc, callee frame, frames from the option's innermost up to its callee)
            options: List[Tuple[int, int, Dict[str, Any], List[Dict[str, Any]]]] = []
            for c in chains:
                for i in range(len(c) - 1, 0, -1):
                    if c[i]["cfa"] == cur["cfa"] and c[i].get("fde_start") == cur.get("fde_start"):
                        nxt = c[i - 1]
                        if nxt.get("ra_slot") is not None:
                            options.append((nxt["ra_slot"], c[i]["pc"], nxt, c[:i]))
                        break
            for d_ra, d_callee in self._callee_of(cur, rd):
                options.append((d_callee["ra_slot"], d_ra, d_callee, [d_callee]))
            if not options:
                break
            if len({(o[0], o[1]) for o in options}) > 1:
                ambiguous += 1
            level_sp = cur.get("sp") if cur.get("sp") is not None else cur["cfa"]
            # (0) a direct call instruction before the caller PC names its callee: other callees are stale
            #     (on x86 every callee of a frame stores its RA in the same slot, so this is decisive there)
            matching = []
            for o in options:
                kind, target = self.call_site(o[1])
                if kind != CALL_DIRECT or target is None or o[2].get("fde_start") == target:
                    matching.append(o)
            if matching:
                options = matching
            if changed:
                plausible = [o for o in options if activity_depth(o[3], level_sp) <= 1]
                if plausible:
                    options = plausible
            slot, caller_pc, nxt, _below = max(options, key=lambda o: (o[1], o[0]))
            cur["pc"] = caller_pc
            cur["lookup_pc"] = caller_pc - 1
            cur = dict(nxt)
            refined.append(cur)
        if ambiguous:
            notes.append(f"running sample: {ambiguous} level(s) had several plausible callees (live and stale "
                         "frames); chosen by changed-word activity, then latest call site, then topmost slot")
        frames = list(reversed(refined))
        for k, f in enumerate(frames):
            f["index"] = k
        return frames, STOP_OUTERMOST, notes

    def _entry_frame(self, func: int, cfa: int, regs: Dict[int, int], ra_slot: int) -> Dict[str, Any]:
        """Frame of a callee identified from a call target (PC unknown: reported as the entry point)."""
        A = self.arch
        callee_sp: Optional[int] = None
        _m, cfde, offs = self._callee_ra_offsets(func)
        regs = dict(regs)
        if offs:
            # body row of the callee (its PC is unknown): the row in effect over the longest PC range
            body = max((r for _k, r in offs), key=lambda r: getattr(r, "span", 0))
            if body.cfa_reg == A.sp_reg:
                callee_sp = cfa - body.cfa_offset
            elif body.cfa_reg == A.fp_reg:
                regs[A.fp_reg] = cfa - body.cfa_offset
        return {
            "index": 0,
            "pc": func,
            "lookup_pc": func,
            "sp": callee_sp,
            "cfa": cfa,
            "regs": regs,
            "unwind": UNWIND_RUNNING,
            "estimated": True,
            "fde_start": func,
            "cfi_source": cfde.source if cfde is not None else None,
            "pac_signed_ra": False,
            "pc_is_function_entry": True,
            "unwound_via": "LEAF_CALL_TARGET_RECOVERY",
            "ra_slot": ra_slot,
        }

    def _walk_cfi_only(self, st: _State, rd: StackReader, frames: List[Dict[str, Any]], max_frames: int) -> str:
        A = self.arch
        seen = set()
        while len(frames) < max_frames:
            if (st.pc, st.sp) in seen:
                return "loop"
            seen.add((st.pc, st.sp))
            mod, fde, row, why = self._row(st.pc, st.exact_pc)
            if row is None or row.cfa_expr is not None:
                return why or "cfa_expression"
            base = st.regs.get(row.cfa_reg) if row.cfa_reg is not None else None
            if base is None and row.cfa_reg == A.fp_reg:
                inf = self._infer_frame_pointer(st, row, fde, mod, rd)
                if inf is not None:
                    st.regs[A.fp_reg] = inf[0]
                    base = inf[0]
            if base is None:
                return "cfa_register_unknown"
            cfa = base + row.cfa_offset
            fr = self._emit(frames, st, cfa, fde, mod, row)
            ra_rule = row.rules.get(A.ra_reg)
            if ra_rule is not None and ra_rule[0] == R_OFFSET:
                fr["ra_slot"] = cfa + ra_rule[1]
            new_regs, stop, ra, _u = self._apply_row(st, row, cfa, rd)
            if stop == STOP_OUTERMOST:
                return STOP_OUTERMOST
            if stop is not None or ra is None or new_regs is None:
                return stop or "ra_unknown"
            ra = self.strip_ra(ra)
            if ra == 0:
                return _OUTERMOST_ZERO_RA  # weaker than an explicit "RA undefined" CFI marker
            if cfa < (st.sp or 0) or not self.in_code(ra):
                return "invalid"
            new_regs[A.sp_reg] = cfa
            st = _State(pc=ra, sp=cfa, regs=new_regs, exact_pc=False, method=st.method, estimated=True)
        return "max_frames"

    def _callee_of(self, frame: Dict[str, Any], rd: StackReader) -> List[Tuple[int, Dict[str, Any]]]:
        """For ``frame`` (sp known), every possible callee below it: slots holding a return address
        into ``frame``'s function, after a direct call whose target's CFI places that RA exactly there."""
        A = self.arch
        p = A.ptr_size
        sp = frame.get("sp")
        fstart = frame.get("fde_start") or self.function_start(frame["lookup_pc"])
        if sp is None or fstart is None:
            return []
        fmod = self.module_for(fstart)
        fend = None
        if fmod and fmod.image:
            fde = fmod.image.find_fde(fstart - fmod.bias)
            if fde is not None:
                fend = fde.pc_end + fmod.bias
        found: List[Tuple[int, Dict[str, Any]]] = []
        # x86: a call pushes the RA at exactly sp - 8; aarch64: the callee stores x30 at CFA + k
        slots = [sp - p] if A.name == "x86_64" else range(sp - p, max(sp - 4096, rd.lo) - 1, -p)
        for s in slots:
            w = rd.word(s)
            if w is None:
                continue
            ra = self.strip_ra(w)
            if fend is not None:
                if not (fstart < ra <= fend):
                    continue
            elif self.function_start(ra - 1) != fstart:
                continue
            kind, target = self.call_site(ra)
            if kind != CALL_DIRECT or target is None or self.is_plt_target(target):
                continue  # callee identity unknown: its frame cannot be placed
            anchor = self._anchor_from_slot(s, target, rd)
            if anchor is None or anchor[0] != sp:
                continue
            found.append((ra, self._entry_frame(target, anchor[0], anchor[1], s)))
            if len(found) >= 8:
                break
        return found


def make_unwinder_for_process(arch: Optional[str], mappings: Sequence[Dict[str, Any]],
                              read_memory: Callable[[int, int], Tuple[Optional[bytes], str, Optional[str]]],
                              endian: str = "little", pid: Optional[int] = None,
                              extra_images: Optional[Dict[str, str]] = None) -> Optional[CfiUnwinder]:
    """Factory used by the thread inspectors; None when the architecture is not implemented."""
    if not arch_supported(arch):
        return None

    def resolver(path: str) -> Optional[str]:
        if os.path.isfile(path):
            return path
        if pid is not None:
            alt = f"/proc/{int(pid)}/root{path}"
            if os.path.isfile(alt):
                return alt
        return None

    return CfiUnwinder(arch or "", mappings, read_memory, endian=endian, file_resolver=resolver,
                       extra_images=extra_images)


def parse_proc_syscall(text: str) -> Dict[str, Any]:
    """Parse /proc/PID/task/TID/syscall: ``nr a0..a5 sp pc`` / ``-1 sp pc`` / ``running``."""
    t = (text or "").strip()
    if not t:
        return {"state": "unavailable"}
    if t.startswith("running"):
        return {"state": "running"}
    parts = t.split()
    try:
        nr = int(parts[0])
    except ValueError:
        return {"state": "unavailable"}
    out: Dict[str, Any] = {"state": "blocked" if nr >= 0 else "not_in_syscall", "nr": nr}
    try:
        if nr >= 0 and len(parts) >= 9:
            out["args"] = [int(x, 16) for x in parts[1:7]]
            out["sp"] = int(parts[7], 16)
            out["pc"] = int(parts[8], 16)
        elif nr < 0 and len(parts) >= 3:
            out["sp"] = int(parts[1], 16)
            out["pc"] = int(parts[2], 16)
    except ValueError:
        pass
    return out
