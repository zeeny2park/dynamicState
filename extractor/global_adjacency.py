"""IMP-009 (2): global arrays overrun into the next global (DWARF layout, zero-stop reads).

For every DWARF array variable of the main executable with a known size (``.data`` / ``.bss``), the object laid
out right after it is found by address - from DWARF *and* the ELF symbol table, so a symbol without DWARF in
between (a copy-relocated ``stdout``, compiler data) breaks the adjacency instead of being skipped - and its value
is checked against its type:

* ``bool`` / ``_Bool`` holding a byte other than 0 / 1;
* an enum outside its enumerators (bit-flag enums: any OR of their power-of-two enumerators is valid);
* a pointer that is not NULL, not a small integer sentinel, not -1-like, and points into no mapping.

(A struct / array neighbour is checked through the member / element at its first byte - the first bytes an
overrun reaches.)  The neighbour must be invalid in two reads ``interval_s`` apart, the array's last bytes must be
non-zero (a linear overrun fills the array to its end) and alignment padding between the two must be non-zero
too.  Result: an *adjacent-overwrite candidate* naming both variables, probable at most.

Weak signal, reported as a candidate only (never a finding by itself): the neighbour's value changed between the
reads while the array's tail changed too.

Conservative by design (false positives are worse than misses): a neighbour of an integer / float / char type
has no invalid values and is never reported; an overrun that writes plausible values is invisible.
"""

import os
import struct
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

_BOOL_NAMES = ("_Bool", "bool")


def elf_objects(path: str, max_bytes: int = 256 * 1024 * 1024) -> List[Tuple[int, int, bytes]]:
    """(st_value, st_size, name) of the defined data objects (STT_OBJECT / STT_TLS excluded) of an ELF64 LE file."""
    out: List[Tuple[int, int, bytes]] = []
    try:
        if os.path.getsize(path) > max_bytes:
            return out
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return out
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        return out
    e_shoff, = struct.unpack_from("<Q", data, 0x28)
    e_shentsize, e_shnum, _ = struct.unpack_from("<HHH", data, 0x3A)
    if not e_shoff or e_shentsize < 64 or e_shoff + e_shnum * e_shentsize > len(data):
        return out
    secs = []
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        _name, typ, _flags, _addr, off, size, link, _info, _align, entsize = struct.unpack_from("<IIQQQQIIQQ", data, o)
        secs.append((typ, off, size, link, entsize))
    for typ, off, size, link, entsize in secs:
        if typ not in (2, 11) or entsize < 24 or link >= len(secs):
            continue
        str_off = secs[link][1]
        for k in range(size // entsize):
            so = off + k * entsize
            if so + 24 > len(data):
                break
            st_name, st_info, _o, st_shndx, st_value, st_size = struct.unpack_from("<IBBHQQ", data, so)
            if st_shndx == 0 or (st_info & 0xF) != 1 or not st_value:
                continue
            e = data.find(b"\x00", str_off + st_name)
            out.append((st_value, st_size, data[str_off + st_name:e]))
    return out


class GlobalAdjacencyChecker:
    def __init__(self, adapter: Any, pid: int, idx: Any, bias: int, is_dyn: bool, exe_path: Optional[str],
                 maps: List[Dict[str, Any]], reader: Any = None, interval_s: float = 0.03,
                 sleep: Callable[[float], None] = time.sleep, max_pairs: int = 4096) -> None:
        self.adapter = adapter
        self.pid = int(pid)
        self.idx = idx
        self.bias = int(bias) if is_dyn else 0
        self.exe_path = exe_path
        self.maps = maps
        self.reader = reader
        self.interval_s = interval_s
        self.sleep = sleep
        self.max_pairs = max_pairs
        self.bytes_read = 0
        self._ranges = sorted((int(m.get("start_int") or 0), int(m.get("end_int") or 0)) for m in maps)

    # ------------------------------------------------------------------ types
    def _canon(self, off: Optional[int]):
        return self.idx.resolve_canonical_type(off) if off is not None else None

    def _size(self, off: Optional[int], depth: int = 0) -> int:
        t = self._canon(off)
        if t is None or depth > 16:
            return 0
        if t.tag in ("DW_TAG_pointer_type", "DW_TAG_reference_type", "DW_TAG_rvalue_reference_type"):
            return 8
        if t.tag == "DW_TAG_array_type":
            if t.byte_size:
                return int(t.byte_size)
            if t.array_count:
                return int(t.array_count) * self._size(t.target_type_offset, depth + 1)
            return 0
        return int(t.byte_size or 0)

    def _first_scalar(self, off: Optional[int], depth: int = 0):
        """Type of the scalar at offset 0 of an object of type ``off`` (struct first member / array element 0)."""
        t = self._canon(off)
        if t is None or depth > 16:
            return None
        if t.tag in ("DW_TAG_structure_type", "DW_TAG_class_type"):
            mems = [m for m in t.members if int(m.offset or 0) == 0 and m.type_offset is not None]
            bases = getattr(t, "base_classes", None) or []
            if bases or not mems:
                return None
            return self._first_scalar(mems[0].type_offset, depth + 1)
        if t.tag == "DW_TAG_array_type":
            return self._first_scalar(t.target_type_offset, depth + 1)
        return t

    def _mapped(self, v: int) -> bool:
        for s, e in self._ranges:
            if s <= v < e:
                return True
        return False

    def _invalid(self, t: Any, raw: bytes) -> Optional[str]:
        if t is None or not raw:
            return None
        if t.tag == "DW_TAG_base_type" and (t.name or "") in _BOOL_NAMES and int(t.byte_size or 1) == 1:
            return None if raw[0] in (0, 1) else "bool holds 0x%02x (only 0 or 1 are valid)" % raw[0]
        if t.tag == "DW_TAG_enumeration_type" and t.enum_values:
            n = int(t.byte_size or 4)
            if n not in (1, 2, 4, 8) or len(raw) < n:
                return None
            v = int.from_bytes(raw[:n], "little", signed=False)
            sv = int.from_bytes(raw[:n], "little", signed=True)
            vals = set(int(x) for x in t.enum_values)
            if v in vals or sv in vals:
                return None
            nz = [x for x in vals if x > 0]
            if nz and all(x & (x - 1) == 0 for x in nz):
                allbits = 0
                for x in nz:
                    allbits |= x
                if v & ~allbits == 0:
                    return None                      # bit-flag enum: a combination of its flags
            return "enum %s holds %d, which is none of its enumerators" % (t.name or "", sv)
        if t.tag == "DW_TAG_pointer_type" and len(raw) >= 8:
            v = struct.unpack_from("<Q", raw, 0)[0]
            if v == 0 or v < 0x10000 or v >= 0xFFFFFFFFFFFF0000:
                return None                          # NULL, small sentinels, -1-like sentinels
            if self._mapped(v):
                return None
            return "pointer holds 0x%x, which points into no mapping of the process" % v
        return None

    # ------------------------------------------------------------------ layout
    def pairs(self) -> List[Dict[str, Any]]:
        vs: Dict[int, Tuple[Any, int]] = {}
        for v in list(self.idx.global_variables) + list(self.idx.static_variables):
            if v.link_time_address is None or v.is_declaration or not v.name or getattr(v, "is_tls", False):
                continue
            size = self._size(v.type_offset)
            if size <= 0:
                continue
            a = v.link_time_address + self.bias
            if a not in vs:
                vs[a] = (v, size)
        objs = [(a + self.bias, s) for a, s, _n in elf_objects(self.exe_path)] if self.exe_path else []
        starts = sorted(set(list(vs) + [a for a, _ in objs]))
        out = []
        import bisect
        for a in sorted(vs):
            v, size = vs[a]
            t = self._canon(v.type_offset)
            if t is None or t.tag != "DW_TAG_array_type":
                continue
            end = a + size
            i = bisect.bisect_left(starts, end)
            if i >= len(starts):
                continue
            b = starts[i]
            if b - end >= 64 or b not in vs:
                continue                     # neighbour too far, or an object without DWARF comes first
            if any(a < s < end for s in starts[bisect.bisect_right(starts, a):i]):
                continue                     # something starts inside the array (aliases / unions): skip
            nv, nsize = vs[b]
            nt = self._first_scalar(nv.type_offset)
            if nt is None or nt.tag not in ("DW_TAG_base_type", "DW_TAG_enumeration_type", "DW_TAG_pointer_type"):
                continue
            if nt.tag == "DW_TAG_base_type" and (nt.name or "") not in _BOOL_NAMES:
                continue                     # integers / floats / chars: every bit pattern is valid
            if not (self._mapped(a) and self._mapped(b)):
                continue
            out.append({"array": v, "array_addr": a, "array_size": size, "neighbour": nv, "neighbour_addr": b,
                        "neighbour_size": min(nsize, 16), "scalar_type": nt, "gap": b - end})
            if len(out) >= self.max_pairs:
                break
        return out

    def _read(self, ranges: List[Tuple[int, int]]) -> List[Optional[bytes]]:
        if self.reader is not None:
            return self.reader.read_ranges(ranges)
        res = self.adapter.read_memory_batch(self.pid, ranges)
        out = []
        for r in res:
            d = r[0] if r else None
            out.append(bytes(d) if d else None)
            self.bytes_read += len(d or b"")
        return out

    def check(self) -> Dict[str, Any]:
        pairs = self.pairs()
        res: Dict[str, Any] = {"arrays_with_typed_neighbour": len(pairs), "candidates": [], "change_candidates": []}
        if not pairs:
            return res
        rngs = []
        for p in pairs:
            tail = min(16, p["array_size"])
            p["tail"] = tail
            rngs.append((p["array_addr"] + p["array_size"] - tail, tail + p["gap"] + p["neighbour_size"]))
        first = self._read(rngs)
        self.sleep(self.interval_s)
        second = self._read(rngs)
        for p, d1, d2 in zip(pairs, first, second):
            if not d1 or not d2 or len(d1) < len(d2) or len(d1) < p["tail"] + p["gap"] + 1:
                continue
            tail, gap = p["tail"], p["gap"]
            nb1, nb2 = d1[tail + gap:], d2[tail + gap:]
            why1 = self._invalid(p["scalar_type"], nb1)
            why2 = self._invalid(p["scalar_type"], nb2)
            arr_tail = d2[:tail]
            pad = d2[tail:tail + gap]
            a_name, n_name = p["array"].name, p["neighbour"].name
            if why1 and why2 and any(arr_tail[-min(8, tail):]) and (not pad or all(pad)):
                text = arr_tail.rstrip(b"\x00")
                res["candidates"].append({
                    "kind": "global_adjacent_overwrite",
                    "status": "probable",
                    "overflowed_array": {"variable": a_name, "variable_path": a_name, "size": p["array_size"],
                                         "address": "0x%x" % p["array_addr"]},
                    "overwritten_neighbour": {"variable": n_name, "variable_path": n_name,
                                              "address": "0x%x" % p["neighbour_addr"],
                                              "value_bytes": nb2[:8].hex(), "invalid_because": why2},
                    "padding_bytes": gap,
                    "array_tail_hex": arr_tail.hex(),
                    "array_tail_printable": bool(text) and all(0x20 <= c < 0x7f for c in text),
                    "description": "global %s (%d bytes) is followed by %s, whose value is invalid for its type (%s) "
                                   "while the array is filled to its last byte: adjacent-overwrite candidate (an "
                                   "overrun of %s into %s)" % (a_name, p["array_size"], n_name, why2, a_name, n_name)})
            elif nb1 != nb2 and d1[:tail] != d2[:tail]:
                res["change_candidates"].append({
                    "array": a_name, "neighbour": n_name,
                    "note": "the neighbour's value changed while the array's tail changed too, between two reads "
                            "%.0f ms apart: a candidate only (normal code may write both)" % (self.interval_s * 1000)})
        return res
