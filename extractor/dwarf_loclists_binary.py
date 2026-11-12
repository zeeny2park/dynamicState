"""Binary reader for DWARF location lists (.debug_loc / .debug_loclists).

`readelf --debug-dump=info|loc` text is toolchain-version dependent: binutils 2.38 does not know the DWARF 5
forms DW_FORM_loclistx (0x22) / DW_FORM_rnglistx (0x23) that clang 14+ emits, so it prints an empty
DW_AT_location and a "Warning: Unrecognized form: 0x22" and the text scrapers find no lists at all.  This module
reads the section bytes directly (DWARF 2-5, ELF64/ELF32, little/big endian, SHF_COMPRESSED sections) so the
result does not depend on the readelf version.

Public API:
    read_location_lists(path) -> LocationListData
        .table    {list section offset: [(start_pc, end_pc, "DW_OP_... (reg)")]}   (same shape as
                  dwarf_evaluator.parse_debug_loc_table)
        .by_die   {DIE offset in .debug_info: list section offset}   for DW_AT_location attributes that are lists

The key of a list is the absolute offset of its first entry in .debug_loc / .debug_loclists, which is also what
readelf prints as the "(location list)" offset.
"""
from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

DW_AT_location = 0x02
DW_AT_low_pc = 0x11
DW_AT_addr_base = 0x73
DW_AT_loclists_base = 0x8C
DW_AT_GNU_addr_base = 0x2133

DW_FORM_addr, DW_FORM_block2, DW_FORM_block4, DW_FORM_data2, DW_FORM_data4, DW_FORM_data8 = 1, 3, 4, 5, 6, 7
DW_FORM_string, DW_FORM_block, DW_FORM_block1, DW_FORM_data1, DW_FORM_flag, DW_FORM_sdata = 8, 9, 10, 11, 12, 13
DW_FORM_strp, DW_FORM_udata, DW_FORM_ref_addr, DW_FORM_ref1, DW_FORM_ref2, DW_FORM_ref4 = 14, 15, 16, 17, 18, 19
DW_FORM_ref8, DW_FORM_ref_udata, DW_FORM_indirect, DW_FORM_sec_offset, DW_FORM_exprloc = 20, 21, 22, 23, 24
DW_FORM_flag_present, DW_FORM_strx, DW_FORM_addrx, DW_FORM_ref_sup4, DW_FORM_strp_sup = 25, 26, 27, 28, 29
DW_FORM_data16, DW_FORM_line_strp, DW_FORM_ref_sig8, DW_FORM_implicit_const = 30, 31, 32, 33
DW_FORM_loclistx, DW_FORM_rnglistx, DW_FORM_ref_sup8, DW_FORM_strx1, DW_FORM_strx2 = 34, 35, 36, 37, 38
DW_FORM_strx3, DW_FORM_strx4, DW_FORM_addrx1, DW_FORM_addrx2, DW_FORM_addrx3, DW_FORM_addrx4 = 39, 40, 41, 42, 43, 44
DW_FORM_GNU_addr_index, DW_FORM_GNU_str_index, DW_FORM_GNU_ref_alt, DW_FORM_GNU_strp_alt = 0x1F01, 0x1F02, 0x1F20, 0x1F21

_ADDRX_FORMS = (DW_FORM_addrx, DW_FORM_addrx1, DW_FORM_addrx2, DW_FORM_addrx3, DW_FORM_addrx4, DW_FORM_GNU_addr_index)

_REG_X86_64 = ["rax", "rdx", "rcx", "rbx", "rsi", "rdi", "rbp", "rsp"] + [f"r{i}" for i in range(8, 16)] + ["rip"] \
    + [f"xmm{i}" for i in range(16)]
_EM_X86_64, _EM_AARCH64 = 62, 183


class _Reader:
    __slots__ = ("d", "p", "e")

    def __init__(self, data: bytes, pos: int = 0, endian: str = "<"):
        self.d, self.p, self.e = data, pos, endian

    def u(self, n: int) -> int:
        if self.p + n > len(self.d):
            raise EOFError
        v = int.from_bytes(self.d[self.p:self.p + n], "little" if self.e == "<" else "big")
        self.p += n
        return v

    def uleb(self) -> int:
        r = s = 0
        while True:
            b = self.u(1)
            r |= (b & 0x7F) << s
            s += 7
            if not b & 0x80:
                return r

    def sleb(self) -> int:
        r = s = 0
        while True:
            b = self.u(1)
            r |= (b & 0x7F) << s
            s += 7
            if not b & 0x80:
                if b & 0x40:
                    r -= 1 << s
                return r

    def cstr(self) -> bytes:
        end = self.d.index(b"\0", self.p)
        v = self.d[self.p:end]
        self.p = end + 1
        return v


@dataclass
class LocationListData:
    table: Dict[int, List[Tuple[int, int, str]]] = field(default_factory=dict)
    by_die: Dict[int, int] = field(default_factory=dict)


def _read_sections(path: str) -> Tuple[Dict[str, bytes], str, int]:
    """Return ({debug section name: bytes}, endian, e_machine)."""
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] != b"\x7fELF":
        raise ValueError("not an ELF file")
    is64 = data[4] == 2
    endian = "<" if data[5] == 1 else ">"
    machine = struct.unpack_from(endian + "H", data, 18)[0]
    if is64:
        shoff, = struct.unpack_from(endian + "Q", data, 0x28)
        shentsize, shnum, shstrndx = struct.unpack_from(endian + "HHH", data, 0x3A)
        fmt = endian + "IIQQQQ"
    else:
        shoff, = struct.unpack_from(endian + "I", data, 0x20)
        shentsize, shnum, shstrndx = struct.unpack_from(endian + "HHH", data, 0x2E)
        fmt = endian + "IIIIII"
    hdrs = [struct.unpack_from(fmt, data, shoff + i * shentsize) for i in range(shnum)]
    stroff = hdrs[shstrndx][4]
    out: Dict[str, bytes] = {}
    for name, typ, flags, _addr, off, size in hdrs:
        if typ == 8:  # NOBITS
            continue
        end = data.index(b"\0", stroff + name)
        nm = data[stroff + name:end].decode("latin-1")
        if nm.startswith(".zdebug_"):
            nm = "." + nm[2:]
        if not nm.startswith(".debug_"):
            continue
        raw = data[off:off + size]
        if flags & 0x800:  # SHF_COMPRESSED
            raw = zlib.decompress(raw[24 if is64 else 12:])
        out[nm] = raw
    return out, endian, machine


def _render_expr(blob: bytes, endian: str, addr_size: int, machine: int) -> str:
    """Render a DWARF expression in the text style of `readelf --debug-dump` (what the evaluator matches on)."""

    def rn(n: int) -> str:
        if machine == _EM_X86_64:
            return _REG_X86_64[n] if n < len(_REG_X86_64) else f"r{n}"
        if machine == _EM_AARCH64:
            if n == 31:
                return "sp"
            return f"x{n}" if n < 31 else (f"v{n - 64}" if 64 <= n < 96 else f"r{n}")
        return f"r{n}"

    r = _Reader(blob, 0, endian)
    parts: List[str] = []
    simple = {0x06: "deref", 0x12: "dup", 0x13: "drop", 0x14: "over", 0x16: "swap", 0x17: "rot", 0x19: "abs",
              0x1A: "and", 0x1B: "div", 0x1C: "minus", 0x1D: "mod", 0x1E: "mul", 0x1F: "neg", 0x20: "not",
              0x21: "or", 0x22: "plus", 0x24: "shl", 0x25: "shr", 0x26: "shra", 0x27: "xor", 0x96: "nop",
              0x9C: "call_frame_cfa", 0x9F: "stack_value", 0x9B: "form_tls_address", 0xE0: "GNU_push_tls_address",
              0x2E: "ne", 0x29: "eq", 0x2A: "ge", 0x2B: "gt", 0x2C: "le", 0x2D: "lt"}
    try:
        while r.p < len(blob):
            op = r.u(1)
            if op == 0x03:
                parts.append(f"DW_OP_addr: {r.u(addr_size):x}")
            elif 0x30 <= op <= 0x4F:
                parts.append(f"DW_OP_lit{op - 0x30}")
            elif 0x50 <= op <= 0x6F:
                parts.append(f"DW_OP_reg{op - 0x50} ({rn(op - 0x50)})")
            elif 0x70 <= op <= 0x8F:
                parts.append(f"DW_OP_breg{op - 0x70} ({rn(op - 0x70)}): {r.sleb()}")
            elif op == 0x90:
                n = r.uleb()
                parts.append(f"DW_OP_regx: {n} ({rn(n)})")
            elif op == 0x92:
                n = r.uleb()
                parts.append(f"DW_OP_bregx: {n} ({rn(n)}) {r.sleb()}")
            elif op == 0x91:
                parts.append(f"DW_OP_fbreg: {r.sleb()}")
            elif op == 0x23:
                parts.append(f"DW_OP_plus_uconst: {r.uleb()}")
            elif op == 0x08:
                parts.append(f"DW_OP_const1u: {r.u(1)}")
            elif op == 0x09:
                v = r.u(1)
                parts.append(f"DW_OP_const1s: {v - 256 if v > 127 else v}")
            elif op == 0x0A:
                parts.append(f"DW_OP_const2u: {r.u(2)}")
            elif op == 0x0B:
                v = r.u(2)
                parts.append(f"DW_OP_const2s: {v - 65536 if v > 32767 else v}")
            elif op == 0x0C:
                parts.append(f"DW_OP_const4u: {r.u(4)}")
            elif op == 0x0D:
                v = r.u(4)
                parts.append(f"DW_OP_const4s: {v - (1 << 32) if v >> 31 else v}")
            elif op == 0x0E:
                parts.append(f"DW_OP_const8u: {r.u(8)}")
            elif op == 0x0F:
                v = r.u(8)
                parts.append(f"DW_OP_const8s: {v - (1 << 64) if v >> 63 else v}")
            elif op == 0x10:
                parts.append(f"DW_OP_constu: {r.uleb()}")
            elif op == 0x11:
                parts.append(f"DW_OP_consts: {r.sleb()}")
            elif op == 0x93:
                parts.append(f"DW_OP_piece: {r.uleb()} (bytes)")
            elif op == 0x9D:
                a = r.uleb()
                parts.append(f"DW_OP_bit_piece: size: {a} offset: {r.uleb()}")
            elif op == 0x94:
                parts.append(f"DW_OP_deref_size: {r.u(1)}")
            elif op in (0xA3, 0xF3):
                n = r.uleb()
                inner = _render_expr(r.d[r.p:r.p + n], endian, addr_size, machine)
                r.p += n
                parts.append(f"{'DW_OP_entry_value' if op == 0xA3 else 'DW_OP_GNU_entry_value'}: ({inner})")
            elif op in (0xA0, 0xF2):
                ref = r.u(4)
                parts.append(f"DW_OP_{'implicit_pointer' if op == 0xA0 else 'GNU_implicit_pointer'}: <0x{ref:x}> {r.sleb()}")
            elif op == 0xA5:
                n = r.uleb()
                parts.append(f"DW_OP_regval_type: {n} ({rn(n)}) <0x{r.uleb():x}>")
            elif op == 0xFA:
                parts.append(f"DW_OP_GNU_parameter_ref: <0x{r.u(4):x}>")
            elif op == 0xF0:
                parts.append("DW_OP_GNU_uninit")
            elif op in (0xA8, 0xA9):
                parts.append(f"DW_OP_{'convert' if op == 0xA8 else 'reinterpret'} <0x{r.uleb():x}>")
            elif op == 0x9E:
                n = r.uleb()
                parts.append(f"DW_OP_implicit_value: {n} byte block")
                r.p += n
            elif op in (0xA1, 0xFB):
                parts.append(f"DW_OP_addrx: {r.uleb()}")
            elif op == 0xA2:
                parts.append(f"DW_OP_constx: {r.uleb()}")
            elif op in simple:
                parts.append(f"DW_OP_{simple[op]}")
            else:
                parts.append(f"DW_OP_0x{op:x}")
                break  # operand layout unknown
    except EOFError:
        pass
    return "; ".join(parts)


def _read_form(r: _Reader, form: int, off_size: int, addr_size: int, version: int, implicit: int):
    """Read one attribute value; returns ("int"|"block"|"other", value)."""
    if form == DW_FORM_addr:
        return "int", r.u(addr_size)
    if form in (DW_FORM_data1, DW_FORM_ref1, DW_FORM_flag, DW_FORM_strx1, DW_FORM_addrx1):
        return "int", r.u(1)
    if form in (DW_FORM_data2, DW_FORM_ref2, DW_FORM_strx2, DW_FORM_addrx2):
        return "int", r.u(2)
    if form in (DW_FORM_strx3, DW_FORM_addrx3):
        return "int", r.u(3)
    if form in (DW_FORM_data4, DW_FORM_ref4, DW_FORM_ref_sup4, DW_FORM_strx4, DW_FORM_addrx4):
        return "int", r.u(4)
    if form in (DW_FORM_data8, DW_FORM_ref8, DW_FORM_ref_sig8, DW_FORM_ref_sup8):
        return "int", r.u(8)
    if form == DW_FORM_data16:
        r.p += 16
        return "other", None
    if form in (DW_FORM_udata, DW_FORM_ref_udata, DW_FORM_strx, DW_FORM_addrx, DW_FORM_loclistx,
                DW_FORM_rnglistx, DW_FORM_GNU_addr_index, DW_FORM_GNU_str_index):
        return "int", r.uleb()
    if form == DW_FORM_sdata:
        return "int", r.sleb()
    if form in (DW_FORM_strp, DW_FORM_line_strp, DW_FORM_sec_offset, DW_FORM_strp_sup, DW_FORM_GNU_ref_alt,
                DW_FORM_GNU_strp_alt):
        return "int", r.u(off_size)
    if form == DW_FORM_ref_addr:
        return "int", r.u(addr_size if version <= 2 else off_size)
    if form == DW_FORM_string:
        r.cstr()
        return "other", None
    if form in (DW_FORM_block, DW_FORM_exprloc, DW_FORM_block1, DW_FORM_block2, DW_FORM_block4):
        n = {DW_FORM_block1: 1, DW_FORM_block2: 2, DW_FORM_block4: 4}.get(form)
        n = r.u(n) if n else r.uleb()
        v = r.d[r.p:r.p + n]
        r.p += n
        return "block", v
    if form == DW_FORM_flag_present:
        return "int", 1
    if form == DW_FORM_implicit_const:
        return "int", implicit
    if form == DW_FORM_indirect:
        return _read_form(r, r.uleb(), off_size, addr_size, version, implicit)
    raise ValueError(f"unknown DW_FORM 0x{form:x}")


def _parse_abbrevs(data: bytes, off: int, endian: str) -> Dict[int, Tuple[int, bool, List[Tuple[int, int, int]]]]:
    r = _Reader(data, off, endian)
    out = {}
    while r.p < len(data):
        code = r.uleb()
        if code == 0:
            break
        tag = r.uleb()
        has_children = bool(r.u(1))
        attrs = []
        while True:
            at, form = r.uleb(), r.uleb()
            imp = r.sleb() if form == DW_FORM_implicit_const else 0
            if at == 0 and form == 0:
                break
            attrs.append((at, form, imp))
        out[code] = (tag, has_children, attrs)
    return out


def _addr_index(secs: Dict[str, bytes], addr_base: int, idx: int, addr_size: int, endian: str) -> int:
    a = secs.get(".debug_addr", b"")
    p = addr_base + idx * addr_size
    if p + addr_size > len(a):
        return 0
    return int.from_bytes(a[p:p + addr_size], "little" if endian == "<" else "big")


def _read_loclist_v5(secs, endian, machine, list_off: int, cu_base: int, addr_base: int, table) -> None:
    d = secs[".debug_loclists"]
    asz = 8
    pos = 0
    while pos < len(d):  # find the unit containing the list (for its address size)
        hr = _Reader(d, pos, endian)
        ln = hr.u(4)
        if ln == 0xFFFFFFFF:
            ln = hr.u(8)
        end = hr.p + ln
        if pos <= list_off < end:
            hr.u(2)
            asz = hr.u(1)
            break
        pos = end
    r = _Reader(d, list_off, endian)
    base = cu_base
    entries: List[Tuple[int, int, str]] = []

    def expr() -> str:
        n = r.uleb()
        blob = d[r.p:r.p + n]
        r.p += n
        return _render_expr(blob, endian, asz, machine)

    def ax(i: int) -> int:
        return _addr_index(secs, addr_base, i, asz, endian)

    while r.p < len(d):
        k = r.u(1)
        if k == 0:       # DW_LLE_end_of_list
            break
        if k == 1:       # base_addressx
            base = ax(r.uleb())
        elif k == 2:     # startx_endx
            s, e = ax(r.uleb()), ax(r.uleb())
            entries.append((s, e, expr()))
        elif k == 3:     # startx_length
            s = ax(r.uleb())
            entries.append((s, s + r.uleb(), expr()))
        elif k == 4:     # offset_pair
            a, b = r.uleb(), r.uleb()
            entries.append((base + a, base + b, expr()))
        elif k == 5:     # default_location
            entries.append((0, (1 << (8 * asz)) - 1, expr()))
        elif k == 6:     # base_address
            base = r.u(asz)
        elif k == 7:     # start_end
            s, e = r.u(asz), r.u(asz)
            entries.append((s, e, expr()))
        elif k == 8:     # start_length
            s = r.u(asz)
            entries.append((s, s + r.uleb(), expr()))
        else:
            return  # unknown entry kind: drop this list rather than guess
    table[list_off] = entries


def _read_loclist_v4(secs, endian, machine, list_off: int, cu_base: int, asz: int, table) -> None:
    d = secs[".debug_loc"]
    r = _Reader(d, list_off, endian)
    base = cu_base
    entries: List[Tuple[int, int, str]] = []
    maxa = (1 << (8 * asz)) - 1
    while r.p + 2 * asz <= len(d):
        s, e = r.u(asz), r.u(asz)
        if s == 0 and e == 0:
            break
        if s == maxa:
            base = e
            continue
        n = r.u(2)
        blob = d[r.p:r.p + n]
        r.p += n
        entries.append((base + s, base + e, _render_expr(blob, endian, asz, machine)))
    table[list_off] = entries


def read_location_lists(path: str) -> LocationListData:
    """Parse all location lists referenced by DW_AT_location in .debug_info; never raises (empty on error)."""
    out = LocationListData()
    try:
        secs, endian, machine = _read_sections(path)
        info, abbrev = secs.get(".debug_info"), secs.get(".debug_abbrev")
        if not info or not abbrev or (".debug_loc" not in secs and ".debug_loclists" not in secs):
            return out
        pos = 0
        while pos + 11 <= len(info):
            r = _Reader(info, pos, endian)
            ln = r.u(4)
            osz = 4
            if ln == 0xFFFFFFFF:
                ln, osz = r.u(8), 8
            unit_end = r.p + ln
            ver = r.u(2)
            if ver >= 5:
                utype = r.u(1)
                asz = r.u(1)
                abbrev_off = r.u(osz)
                if utype in (4, 5, 2, 6):  # skeleton/split_compile: dwo_id; type/split_type: signature + offset
                    r.u(8)
                    if utype in (2, 6):
                        r.u(osz)
            else:
                abbrev_off = r.u(osz)
                asz = r.u(1)
            abbrevs = _parse_abbrevs(abbrev, abbrev_off, endian)
            cu_attrs: Dict[object, int] = {}
            pending: List[Tuple[int, str, int]] = []
            first = True
            while r.p < unit_end:
                die_off = r.p
                code = r.uleb()
                if code == 0:
                    continue
                _tag, _children, attrs = abbrevs[code]
                for at, form, imp in attrs:
                    kind, val = _read_form(r, form, osz, asz, ver, imp)
                    if first and kind == "int":
                        if at == DW_AT_low_pc:
                            cu_attrs["low_pc_idx" if form in _ADDRX_FORMS else "low_pc"] = val
                        elif at in (DW_AT_addr_base, DW_AT_GNU_addr_base, DW_AT_loclists_base):
                            cu_attrs[at] = val
                    if at == DW_AT_location and kind == "int":
                        if form == DW_FORM_loclistx:
                            pending.append((die_off, "idx", val))
                        elif form == DW_FORM_sec_offset or (form in (DW_FORM_data4, DW_FORM_data8) and ver < 4):
                            pending.append((die_off, "sec", val))
                first = False
            addr_base = cu_attrs.get(DW_AT_addr_base, cu_attrs.get(DW_AT_GNU_addr_base, 8))
            cu_base = cu_attrs.get("low_pc", 0)
            if "low_pc_idx" in cu_attrs:
                cu_base = _addr_index(secs, addr_base, cu_attrs["low_pc_idx"], asz, endian)
            for die_off, how, val in pending:
                try:
                    if ver >= 5 and ".debug_loclists" in secs:
                        if how == "idx":
                            base = cu_attrs.get(DW_AT_loclists_base, 12)
                            list_off = base + _Reader(secs[".debug_loclists"], base + val * osz, endian).u(osz)
                        else:
                            list_off = val
                        if list_off not in out.table:
                            _read_loclist_v5(secs, endian, machine, list_off, cu_base, addr_base, out.table)
                    elif ".debug_loc" in secs and how == "sec":
                        list_off = val
                        if list_off not in out.table:
                            _read_loclist_v4(secs, endian, machine, list_off, cu_base, asz, out.table)
                    else:
                        continue
                    if list_off in out.table:
                        out.by_die[die_off] = list_off
                except (EOFError, ValueError, IndexError, KeyError):
                    continue
            pos = unit_end
    except Exception:
        return out
    return out
