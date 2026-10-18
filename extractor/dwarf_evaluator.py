"""Phase 2 DWARF Location Evaluation Engine.

Provides dynamic runtime location evaluation and value reconstruction for userspace variables:
1. Inputs: target/debug ELF BinaryIdentity, DwarfSubprogram, link-time instruction address,
   runtime load bias, observation-point register set, frame metadata, variable name, and architecture.
2. Outputs: evaluated value, value hex, type, location description, evaluation status:
   - OBSERVED: value successfully resolved from register or memory.
   - UNAVAILABLE: location valid but inaccessible at current probe point (e.g. PC outside live range).
   - OPTIMIZED_OUT: variable eliminated by compiler or has empty DWARF location.
   - UNSUPPORTED: DWARF feature/opcode not implemented in evaluator.
   - ERROR: Corrupted debug info or unparseable DWARF.
3. Bounded vertical slice:
   - Direct registers (DW_OP_reg* / DW_OP_regx).
   - Simple frame-base relative (DW_OP_fbreg <offset>) using CFA calculation.
   - Basic location-list range selection (.debug_loc / .debug_loclists).
   - Basic scalar types: int8, int16, int32, int64, uint8, uint16, uint32, uint64, float, double, bool, pointer.
"""

from dataclasses import dataclass, field
import os
import re
import struct
import subprocess
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from .debug_image import BinaryIdentity, inspect_elf
from .dwarf_indexer import DwarfIndex, DwarfIndexer, DwarfSubprogram, DwarfType, DwarfVariable
from .ebpf_tracer import (
    STATUS_OBSERVED,
    STATUS_UNAVAILABLE,
    AddressValidator,
    DwarfLocationResolverInterface,
    FrameMetadata,
    TraceValue,
)


# -----------------------------------------------------------------------------
# Evaluation Status Constants
# -----------------------------------------------------------------------------

EVAL_STATUS_OBSERVED = "OBSERVED"
EVAL_STATUS_UNAVAILABLE = "UNAVAILABLE"
EVAL_STATUS_OPTIMIZED_OUT = "OPTIMIZED_OUT"
EVAL_STATUS_UNSUPPORTED = "UNSUPPORTED"
EVAL_STATUS_ERROR = "ERROR"


# -----------------------------------------------------------------------------
# Input Context and Output Result
# -----------------------------------------------------------------------------

@dataclass
class DwarfEvaluationContext:
    """Inputs for DWARF variable location evaluation at a specific observation point."""
    binary_identity: BinaryIdentity
    subprogram: Optional[DwarfSubprogram]
    link_time_address: Optional[int] = None  # Link-time instruction pointer (PC) inside subprogram
    load_bias: int = 0                       # Runtime load bias (runtime_pc - link_time_pc)
    registers: Dict[str, int] = field(default_factory=dict)
    frame_metadata: Optional[FrameMetadata] = None
    variable_name: str = ""
    architecture: str = "x86_64"             # "x86_64", "aarch64", "arm64"
    memory_reader: Optional[Callable[[int, int], Optional[bytes]]] = None  # (address, size) -> bytes
    debug_artifact_path: Optional[str] = None  # Explicit companion debug ELF when binary is stripped


@dataclass
class DwarfLocationResult:
    """Evaluated runtime location and reconstructed value of a variable."""
    variable_name: str
    status: str                              # OBSERVED, UNAVAILABLE, OPTIMIZED_OUT, UNSUPPORTED, ERROR
    location_type: Optional[str] = None      # "register", "stack_memory", "memory", None
    location_description: Optional[str] = None
    evaluated_address: Optional[int] = None
    register_name: Optional[str] = None
    value: Optional[Union[int, float, str, bool]] = None
    value_hex: Optional[str] = None
    type_name: Optional[str] = None
    byte_size: Optional[int] = None
    reason: Optional[str] = None

    def to_trace_value(self) -> TraceValue:
        """Convert to existing TraceValue schema for tracer integration."""
        return TraceValue(
            name=self.variable_name,
            status=self.status,
            value=self.value,
            value_hex=self.value_hex,
            location=self.location_description,
            type_name=self.type_name,
            reason=self.reason,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "variable_name": self.variable_name,
            "status": self.status,
            "location_type": self.location_type,
            "location_description": self.location_description,
            "evaluated_address": f"0x{self.evaluated_address:x}" if self.evaluated_address is not None else None,
            "register_name": self.register_name,
            "value": self.value,
            "value_hex": self.value_hex,
            "type_name": self.type_name,
            "byte_size": self.byte_size,
            "reason": self.reason,
        }


# -----------------------------------------------------------------------------
# Architecture Register Maps
# -----------------------------------------------------------------------------

# DWARF register numbers for x86_64 (System V AMD64 ABI)
X86_64_DWARF_REGS = {
    0: "rax", 1: "rdx", 2: "rcx", 3: "rbx", 4: "rsi", 5: "rdi", 6: "rbp", 7: "rsp",
    8: "r8", 9: "r9", 10: "r10", 11: "r11", 12: "r12", 13: "r13", 14: "r14", 15: "r15",
    16: "rip",
}
# SSE / Floating point registers (xmm0..xmm15: DWARF 17..32)
for i in range(16):
    X86_64_DWARF_REGS[17 + i] = f"xmm{i}"

X86_64_ARG_ALIASES = {
    "rdi": "arg0",
    "rsi": "arg1",
    "rdx": "arg2",
    "rcx": "arg3",
    "r8": "arg4",
    "r9": "arg5",
    "rbp": "fp",
    "rsp": "sp",
    "rip": "pc",
}
for i in range(8):
    X86_64_ARG_ALIASES[f"xmm{i}"] = f"farg{i}"

# DWARF register numbers for AArch64 (AAPCS64)
# 0..30: x0..x30 (x29=fp, x30=lr), 31: sp
AARCH64_DWARF_REGS = {i: f"x{i}" for i in range(31)}
AARCH64_DWARF_REGS[31] = "sp"
# SIMD / FP registers (v0..v31: DWARF 64..95)
for i in range(32):
    AARCH64_DWARF_REGS[64 + i] = f"v{i}"

AARCH64_ARG_ALIASES = {
    "x0": "arg0",
    "x1": "arg1",
    "x2": "arg2",
    "x3": "arg3",
    "x4": "arg4",
    "x5": "arg5",
    "x6": "arg6",
    "x7": "arg7",
    "x29": "fp",
    "x30": "ra",
    "sp": "sp",
}
for i in range(8):
    AARCH64_ARG_ALIASES[f"v{i}"] = f"farg{i}"
    AARCH64_ARG_ALIASES[f"d{i}"] = f"farg{i}"
    AARCH64_ARG_ALIASES[f"s{i}"] = f"farg{i}"


# -----------------------------------------------------------------------------
# Location List Cache & Parser
# -----------------------------------------------------------------------------

_LOC_CACHE: Dict[Tuple[str, int, int, Optional[str]], Dict[int, List[Tuple[int, int, str]]]] = {}
_LOC_ERROR: Dict[Tuple[str, int, int, Optional[str]], str] = {}


def _get_loc_cache_key(path: str) -> Tuple[str, int, int, Optional[str]]:
    abs_path = os.path.abspath(path)
    if not os.path.exists(abs_path):
        return (abs_path, 0, 0, None)
    st = os.stat(abs_path)
    build_id = None
    try:
        from .debug_image import inspect_elf
        ident = inspect_elf(abs_path)
        build_id = ident.build_id
    except Exception:
        pass
    return (abs_path, st.st_mtime_ns, st.st_size, build_id)


def clear_loc_cache() -> None:
    """Clear cached location lists (used in test teardown)."""
    _LOC_CACHE.clear()
    _LOC_ERROR.clear()


def parse_debug_loc_table(artifact_path: str) -> Dict[int, List[Tuple[int, int, str]]]:
    """Parse .debug_loc (DWARF 4) or .debug_loclists (DWARF 5) section using readelf.

    Returns mapping from loc_offset to list of (start_pc, end_pc, expression).
    Ensures that:
    1. Each location-list offset maps only to its own entries.
    2. Range start addresses are never mistakenly treated as list offsets.
    3. Empty lists (<End of list>) map to empty lists.
    4. Base-address selection entries and continuation lines are properly parsed.
    """
    cache_key = _get_loc_cache_key(artifact_path)
    if cache_key in _LOC_CACHE:
        return _LOC_CACHE[cache_key]

    loc_table: Dict[int, List[Tuple[int, int, str]]] = {}
    try:
        cmd = ["readelf", "--debug-dump=loc", cache_key[0]]
        res = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if res.returncode != 0:
            _LOC_ERROR[cache_key] = res.stderr.strip() or f"readelf exited with code {res.returncode}"
            return {}

        lines = res.stdout.splitlines()
        current_list_offset: Optional[int] = None
        current_view_offsets: List[int] = []
        current_entries: List[Tuple[int, int, str]] = []

        # Grammar-driven regex patterns
        # 1. End of list: starts with optional column 1 offset and <End of list>
        end_re = re.compile(r"^\s*([0-9a-fA-F]{1,8})?\s*<End of list>")
        # 2. View pair line: e.g. "    00000000 v000000000000000 v000000000000000 location view pair"
        view_pair_re = re.compile(r"^\s{2,6}([0-9a-fA-F]{1,8})\s+v[0-9a-fA-F]+\s+v[0-9a-fA-F]+\s+location view pair")
        # 3. View header line: e.g. "    00000006 v... views at 00000000 for:"
        view_hdr_re = re.compile(r"^\s{2,6}([0-9a-fA-F]{1,8})\s+v[0-9a-fA-F]+\s+v[0-9a-fA-F]+\s+views at ([0-9a-fA-F]+) for:")
        # 4. Base address line: e.g. "    00000012 0000000000001880 (base address)" or with .debug_addr index
        base_addr_re = re.compile(r"^\s{2,6}([0-9a-fA-F]{1,8})\s+.*\(base address\)")
        # 5. Range entry with column 1 offset: exactly 3 hex tokens before expression
        #    e.g. "    00000000 0000000000001880 0000000000001894 (DW_OP_reg0 (x0))"
        #    Must have 2-6 leading spaces, 1-8 hex digit offset, then start_pc, end_pc, and expression.
        range_with_offset_re = re.compile(r"^\s{2,6}([0-9a-fA-F]{1,8})\s+([0-9a-fA-F]{8,16})\s+([0-9a-fA-F]{8,16})\s+\((.*)$")
        # 6. Range entry without offset (indented continuation line, e.g. after view header or multi-range)
        #    Must have >= 7 leading spaces, start_pc, end_pc, and expression.
        range_no_offset_re = re.compile(r"^\s{7,}([0-9a-fA-F]{8,16})\s+([0-9a-fA-F]{8,16})\s+\((.*)$")

        for line in lines:
            sline = line.strip()
            if not sline:
                continue
            if (
                "Contents of the" in line
                or "Table at Offset" in line
                or "Offset Entries" in line
                or re.match(r"^\s*\[\s*\d+\]", line)
                or "Offset   Begin" in line
                or "Address size:" in line
                or "Length:" in line
                or "DWARF version:" in line
                or "Segment size:" in line
            ):
                continue

            # Check End of list
            m_end = end_re.match(line)
            if m_end:
                end_off = int(m_end.group(1), 16) if m_end.group(1) else None
                if current_list_offset is not None:
                    loc_table[current_list_offset] = list(current_entries)
                    for voff in current_view_offsets:
                        if voff not in loc_table:
                            loc_table[voff] = list(current_entries)
                elif end_off is not None:
                    # Explicitly empty location list at this offset
                    loc_table[end_off] = []
                current_list_offset = None
                current_view_offsets = []
                current_entries = []
                continue

            # Check View Pair (locviews metadata preceding list)
            m_vp = view_pair_re.match(line)
            if m_vp:
                v_off = int(m_vp.group(1), 16)
                current_view_offsets.append(v_off)
                continue

            # Check View Header for list
            m_vh = view_hdr_re.match(line)
            if m_vh:
                off = int(m_vh.group(1), 16)
                if current_list_offset is None:
                    current_list_offset = off
                continue

            # Check Base Address selection entry
            m_base = base_addr_re.match(line)
            if m_base:
                off = int(m_base.group(1), 16)
                if current_list_offset is None:
                    current_list_offset = off
                continue

            # Check Range Entry with Offset in column 1
            m_ro = range_with_offset_re.match(line)
            if m_ro:
                off = int(m_ro.group(1), 16)
                start_pc = int(m_ro.group(2), 16)
                end_pc = int(m_ro.group(3), 16)
                raw_expr = m_ro.group(4)
                expr = raw_expr[:-1] if raw_expr.endswith(")") else raw_expr
                if current_list_offset is None:
                    current_list_offset = off
                current_entries.append((start_pc, end_pc, expr.strip()))
                continue

            # Check Range Entry without Offset (indented continuation line)
            m_rno = range_no_offset_re.match(line)
            if m_rno:
                start_pc = int(m_rno.group(1), 16)
                end_pc = int(m_rno.group(2), 16)
                raw_expr = m_rno.group(3)
                expr = raw_expr[:-1] if raw_expr.endswith(")") else raw_expr
                current_entries.append((start_pc, end_pc, expr.strip()))
                continue

            # Check Expression Continuation Line (multi-line opcode sequence)
            if current_entries and (sline.startswith("DW_OP_") or sline.startswith(";")):
                raw_cont = sline[:-1] if sline.endswith(")") else sline
                prev_start, prev_end, prev_expr = current_entries[-1]
                delim = "; " if not prev_expr.rstrip().endswith(";") and not raw_cont.startswith(";") else " "
                current_entries[-1] = (prev_start, prev_end, (prev_expr + delim + raw_cont).strip())

        # If file finished while inside a list
        if current_list_offset is not None:
            loc_table[current_list_offset] = list(current_entries)
            for voff in current_view_offsets:
                if voff not in loc_table:
                    loc_table[voff] = list(current_entries)

    except Exception as e:
        _LOC_ERROR[cache_key] = str(e)
        return {}

    _LOC_CACHE[cache_key] = loc_table
    return loc_table


# -----------------------------------------------------------------------------
# Scalar Value Unpacking
# -----------------------------------------------------------------------------

def unpack_scalar_from_bytes(
    raw_bytes: bytes,
    type_name: str,
    endianness: str = "little",
    pointer_size: int = 8,
    canonical_type: Optional[DwarfType] = None,
) -> Tuple[Union[int, float, str, bool], str]:
    """Unpack raw memory bytes into typed value and formatted hexadecimal string."""
    endian_prefix = "<" if endianness == "little" else ">"
    clean_name = type_name.lower().strip()

    # 1. Pointer / Address / Reference types
    is_ptr = False
    if canonical_type and canonical_type.tag in ("DW_TAG_pointer_type", "DW_TAG_reference_type", "DW_TAG_rvalue_reference_type"):
        is_ptr = True
    elif clean_name.endswith("*") or clean_name.endswith("&") or "pointer" in clean_name.split():
        is_ptr = True

    if is_ptr:
        fmt = endian_prefix + ("Q" if pointer_size == 8 else "I")
        val = struct.unpack(fmt, raw_bytes[:pointer_size])[0]
        return val, f"0x{val:x}"

    # 2. Floating point types
    is_float32 = False
    is_float64 = False
    if canonical_type and canonical_type.tag == "DW_TAG_base_type":
        c_name = canonical_type.name.lower().strip()
        if c_name in ("float", "float32", "_float32") or (canonical_type.byte_size == 4 and "float" in c_name and "double" not in c_name):
            is_float32 = True
        elif c_name in ("double", "float64", "_float64", "long double") or (canonical_type.byte_size == 8 and "double" in c_name):
            is_float64 = True
    else:
        tokens = clean_name.split()
        if "float" in tokens or clean_name == "float":
            is_float32 = True
        elif "double" in tokens or clean_name == "double" or "long double" in clean_name:
            is_float64 = True

    if is_float32 and len(raw_bytes) >= 4:
        val = struct.unpack(endian_prefix + "f", raw_bytes[:4])[0]
        hex_int = struct.unpack(endian_prefix + "I", raw_bytes[:4])[0]
        return val, f"0x{hex_int:08x}"
    if is_float64 and len(raw_bytes) >= 8:
        val = struct.unpack(endian_prefix + "d", raw_bytes[:8])[0]
        hex_int = struct.unpack(endian_prefix + "Q", raw_bytes[:8])[0]
        return val, f"0x{hex_int:016x}"

    # 3. Boolean
    is_bool = False
    if canonical_type and canonical_type.tag == "DW_TAG_base_type" and canonical_type.name.lower() in ("bool", "_bool"):
        is_bool = True
    elif clean_name in ("bool", "_bool"):
        is_bool = True

    if is_bool:
        val = bool(raw_bytes[0]) if len(raw_bytes) >= 1 else False
        return val, "0x1" if val else "0x0"

    # 4. Integers by size and signedness
    size = len(raw_bytes)
    is_signed = True
    if canonical_type and canonical_type.tag == "DW_TAG_base_type":
        c_name = canonical_type.name.lower().strip()
        if "unsigned" in c_name or c_name.startswith("u") or "size_t" in c_name:
            is_signed = False
    else:
        if "unsigned" in clean_name or clean_name.startswith("u") or "size_t" in clean_name:
            is_signed = False

    if size == 1:
        fmt = endian_prefix + ("b" if is_signed else "B")
        val = struct.unpack(fmt, raw_bytes[:1])[0]
        return val, f"0x{(val & 0xFF):02x}"
    elif size == 2:
        fmt = endian_prefix + ("h" if is_signed else "H")
        val = struct.unpack(fmt, raw_bytes[:2])[0]
        return val, f"0x{(val & 0xFFFF):04x}"
    elif size == 4:
        fmt = endian_prefix + ("i" if is_signed else "I")
        val = struct.unpack(fmt, raw_bytes[:4])[0]
        return val, f"0x{(val & 0xFFFFFFFF):08x}"
    elif size >= 8:
        fmt = endian_prefix + ("q" if is_signed else "Q")
        val = struct.unpack(fmt, raw_bytes[:8])[0]
        return val, f"0x{(val & 0xFFFFFFFFFFFFFFFF):016x}"

    # Fallback: treat as hex integer
    val = int.from_bytes(raw_bytes, byteorder=endianness, signed=is_signed)
    return val, f"0x{val:x}"


def unpack_scalar_from_register(
    reg_val: Union[int, float],
    type_name: str,
    byte_size: int = 4,
    pointer_size: int = 8,
    endianness: str = "little",
    canonical_type: Optional[DwarfType] = None,
) -> Tuple[Union[int, float, str, bool], str]:
    """Cast 64-bit register integer (or float) to typed scalar value and hexadecimal string."""
    endian_prefix = "<" if endianness == "little" else ">"
    clean_name = type_name.lower().strip()

    # 1. Pointer / Address / Reference types
    is_ptr = False
    if canonical_type and canonical_type.tag in ("DW_TAG_pointer_type", "DW_TAG_reference_type", "DW_TAG_rvalue_reference_type"):
        is_ptr = True
    elif clean_name.endswith("*") or clean_name.endswith("&") or "pointer" in clean_name.split():
        is_ptr = True

    if is_ptr:
        mask = 0xFFFFFFFFFFFFFFFF if pointer_size == 8 else 0xFFFFFFFF
        val = (int(reg_val)) & mask
        return val, f"0x{val:x}"

    # 2. Floating point types
    is_float32 = False
    is_float64 = False
    if canonical_type and canonical_type.tag == "DW_TAG_base_type":
        c_name = canonical_type.name.lower().strip()
        if c_name in ("float", "float32", "_float32") or (canonical_type.byte_size == 4 and "float" in c_name and "double" not in c_name):
            is_float32 = True
        elif c_name in ("double", "float64", "_float64", "long double") or (canonical_type.byte_size == 8 and "double" in c_name):
            is_float64 = True
    else:
        tokens = clean_name.split()
        if "float" in tokens or clean_name == "float":
            is_float32 = True
        elif "double" in tokens or clean_name == "double" or "long double" in clean_name:
            is_float64 = True

    if is_float32:
        if isinstance(reg_val, float):
            u32 = struct.unpack(endian_prefix + "I", struct.pack(endian_prefix + "f", reg_val))[0]
            return reg_val, f"0x{u32:08x}"
        else:
            u32 = int(reg_val) & 0xFFFFFFFF
            f_val = struct.unpack(endian_prefix + "f", struct.pack(endian_prefix + "I", u32))[0]
            return f_val, f"0x{u32:08x}"

    if is_float64:
        if isinstance(reg_val, float):
            u64 = struct.unpack(endian_prefix + "Q", struct.pack(endian_prefix + "d", reg_val))[0]
            return reg_val, f"0x{u64:016x}"
        else:
            u64 = int(reg_val) & 0xFFFFFFFFFFFFFFFF
            d_val = struct.unpack(endian_prefix + "d", struct.pack(endian_prefix + "Q", u64))[0]
            return d_val, f"0x{u64:016x}"

    # 3. Boolean
    is_bool = False
    if canonical_type and canonical_type.tag == "DW_TAG_base_type" and canonical_type.name.lower() in ("bool", "_bool"):
        is_bool = True
    elif clean_name in ("bool", "_bool"):
        is_bool = True

    int_reg = int(reg_val)
    if is_bool:
        b_val = bool(int_reg & 0x1)
        return b_val, "0x1" if b_val else "0x0"

    # 4. Integers
    is_signed = True
    if canonical_type and canonical_type.tag == "DW_TAG_base_type":
        c_name = canonical_type.name.lower().strip()
        if "unsigned" in c_name or c_name.startswith("u") or "size_t" in c_name:
            is_signed = False
    else:
        if "unsigned" in clean_name or clean_name.startswith("u") or "size_t" in clean_name:
            is_signed = False

    if byte_size == 1:
        u8 = int_reg & 0xFF
        val = (u8 - 0x100) if (is_signed and (u8 & 0x80)) else u8
        return val, f"0x{u8:02x}"
    elif byte_size == 2:
        u16 = int_reg & 0xFFFF
        val = (u16 - 0x10000) if (is_signed and (u16 & 0x8000)) else u16
        return val, f"0x{u16:04x}"
    elif byte_size == 4:
        u32 = int_reg & 0xFFFFFFFF
        val = (u32 - 0x100000000) if (is_signed and (u32 & 0x80000000)) else u32
        return val, f"0x{u32:08x}"
    else:
        u64 = int_reg & 0xFFFFFFFFFFFFFFFF
        val = (u64 - 0x10000000000000000) if (is_signed and (u64 & 0x8000000000000000)) else u64
        return val, f"0x{u64:016x}"


# -----------------------------------------------------------------------------
# DWARF Location Evaluator Implementation
# -----------------------------------------------------------------------------

class DwarfEvaluator:
    """Evaluates variable locations and values from DWARF index and runtime register/memory context."""

    @classmethod
    def evaluate(cls, context: DwarfEvaluationContext) -> DwarfLocationResult:
        """Evaluate a variable's runtime location and value."""
        var_name = context.variable_name
        if not context.subprogram:
            return DwarfLocationResult(
                variable_name=var_name,
                status=EVAL_STATUS_ERROR,
                reason="Subprogram context is missing or null",
            )

        # Companion debug artifact validation
        if context.debug_artifact_path:
            abs_dbg = os.path.abspath(context.debug_artifact_path)
            if not os.path.exists(abs_dbg):
                return DwarfLocationResult(
                    variable_name=var_name,
                    status=EVAL_STATUS_ERROR,
                    reason=f"Companion debug artifact not found: {abs_dbg}",
                )
            try:
                dbg_ident = inspect_elf(abs_dbg)
                if context.binary_identity.build_id and dbg_ident.build_id:
                    if context.binary_identity.build_id != dbg_ident.build_id:
                        return DwarfLocationResult(
                            variable_name=var_name,
                            status=EVAL_STATUS_ERROR,
                            reason=(
                                f"Companion debug artifact Build ID mismatch: "
                                f"expected {context.binary_identity.build_id}, "
                                f"got {dbg_ident.build_id}"
                            ),
                        )
            except Exception as e:
                return DwarfLocationResult(
                    variable_name=var_name,
                    status=EVAL_STATUS_ERROR,
                    reason=f"Failed to inspect companion debug artifact: {e}",
                )

        if getattr(context.subprogram, "has_unsupported_cfi", False):
            return DwarfLocationResult(
                variable_name=var_name,
                status=EVAL_STATUS_UNSUPPORTED,
                reason="Subprogram uses unsupported complex CFI rule (DW_CFA_def_cfa_expression)",
            )

        if context.link_time_address is None or context.link_time_address < 0:
            return DwarfLocationResult(
                variable_name=var_name,
                status=EVAL_STATUS_UNAVAILABLE,
                reason="Link-time instruction address is unavailable",
            )

        # 1. Find variable in subprogram
        d_var = context.subprogram.get_variable(var_name)
        if not d_var:
            return DwarfLocationResult(
                variable_name=var_name,
                status=EVAL_STATUS_UNAVAILABLE,
                reason=f"Variable '{var_name}' not found in subprogram '{context.subprogram.name}'",
            )

        # Resolve type and byte size
        artifact_path = context.debug_artifact_path or context.binary_identity.path
        d_index = DwarfIndexer.get_index(artifact_path)
        d_type: Optional[DwarfType] = None
        type_name = "unknown"
        byte_size = 4
        if d_var.type_offset:
            d_type = d_index.resolve_canonical_type(d_var.type_offset)
            type_name = d_index.get_type_name(d_var.type_offset)
            if d_type and d_type.byte_size:
                byte_size = d_type.byte_size

        # 2. Check if variable has no location (optimized out by compiler)
        if not d_var.location_expr and d_var.location_list_offset is None:
            return DwarfLocationResult(
                variable_name=var_name,
                status=EVAL_STATUS_OPTIMIZED_OUT,
                type_name=type_name,
                byte_size=byte_size,
                reason="Variable has no location description in DWARF (optimized out by compiler)",
            )

        # 3. Determine active location expression (handling location lists if present)
        loc_expr = d_var.location_expr
        if d_var.location_list_offset is not None:
            loc_table = parse_debug_loc_table(artifact_path)
            if d_var.location_list_offset not in loc_table:
                cache_key = _get_loc_cache_key(artifact_path)
                err_detail = _LOC_ERROR.get(cache_key)
                reason_msg = f"Location list at offset 0x{d_var.location_list_offset:x} not found in debug data (table missing or corrupted)"
                if err_detail:
                    reason_msg += f": {err_detail}"
                return DwarfLocationResult(
                    variable_name=var_name,
                    status=EVAL_STATUS_ERROR,
                    type_name=type_name,
                    byte_size=byte_size,
                    reason=reason_msg,
                )

            entries = loc_table[d_var.location_list_offset]
            if not entries:
                return DwarfLocationResult(
                    variable_name=var_name,
                    status=EVAL_STATUS_OPTIMIZED_OUT,
                    type_name=type_name,
                    byte_size=byte_size,
                    reason=f"Location list at offset 0x{d_var.location_list_offset:x} is explicitly empty (variable eliminated)",
                )

            # Match link_time_address against ranges
            matching_expr: Optional[str] = None
            pc = context.link_time_address
            for start_pc, end_pc, expr in entries:
                if start_pc <= pc < end_pc:
                    matching_expr = expr
                    break

            if not matching_expr:
                return DwarfLocationResult(
                    variable_name=var_name,
                    status=EVAL_STATUS_UNAVAILABLE,
                    location_type="location_list",
                    type_name=type_name,
                    byte_size=byte_size,
                    reason=f"Instruction address 0x{pc:x} is outside variable live ranges in location list",
                )
            loc_expr = matching_expr

        if not loc_expr:
            return DwarfLocationResult(
                variable_name=var_name,
                status=EVAL_STATUS_OPTIMIZED_OUT,
                type_name=type_name,
                byte_size=byte_size,
                reason="No active location expression at this instruction address (variable eliminated)",
            )

        # 4. Evaluate expression
        # Case A: DW_OP_entry_value -> OPTIMIZED_OUT
        if "DW_OP_entry_value" in loc_expr or "DW_OP_GNU_entry_value" in loc_expr:
            return DwarfLocationResult(
                variable_name=var_name,
                status=EVAL_STATUS_OPTIMIZED_OUT,
                type_name=type_name,
                byte_size=byte_size,
                reason="Variable value exists only as DW_OP_entry_value; register no longer holds active value",
            )

        # Case B: Direct register (DW_OP_reg* / DW_OP_regx)
        m_reg = re.search(r"DW_OP_reg(\d+)", loc_expr)
        m_regx = re.search(r"DW_OP_regx:?\s*(\d+)", loc_expr)
        if m_reg or m_regx:
            reg_num = int(m_reg.group(1)) if m_reg else int(m_regx.group(1))
            return cls._evaluate_register_location(context, var_name, reg_num, type_name, byte_size, canonical_type=d_type)

        # Case C: Simple frame-base relative (DW_OP_fbreg <offset>)
        m_fbreg = re.search(r"DW_OP_fbreg:?\s*(-?\d+)", loc_expr)
        if m_fbreg:
            fb_offset = int(m_fbreg.group(1))
            return cls._evaluate_frame_base_location(context, var_name, fb_offset, type_name, byte_size, canonical_type=d_type)

        # Case D: Register-relative base (DW_OP_breg* <offset> / DW_OP_bregx <reg> <offset>)
        m_breg = re.search(r"DW_OP_breg(\d+):?\s*(-?\d+)", loc_expr)
        m_bregx = re.search(r"DW_OP_bregx:?\s*(\d+):?\s*(-?\d+)", loc_expr)
        if m_breg or m_bregx:
            r_num = int(m_breg.group(1)) if m_breg else int(m_bregx.group(1))
            r_off = int(m_breg.group(2)) if m_breg else int(m_bregx.group(2))
            return cls._evaluate_breg_location(context, var_name, r_num, r_off, type_name, byte_size, canonical_type=d_type)

        # Case E: Unsupported DWARF opcode
        # Must NEVER be conflated with OPTIMIZED_OUT!
        return DwarfLocationResult(
            variable_name=var_name,
            status=EVAL_STATUS_UNSUPPORTED,
            type_name=type_name,
            byte_size=byte_size,
            reason=f"Unsupported DWARF location expression: '{loc_expr}'",
        )

    @classmethod
    def _get_register_name(cls, arch: str, reg_num: int) -> Optional[str]:
        """Map DWARF register number to canonical register name."""
        if arch in ("aarch64", "arm64"):
            return AARCH64_DWARF_REGS.get(reg_num)
        return X86_64_DWARF_REGS.get(reg_num)

    @classmethod
    def _lookup_register_value(cls, context: DwarfEvaluationContext, reg_name: str) -> Optional[int]:
        """Look up register value in context.registers using name and aliases."""
        regs = context.registers
        arch = context.architecture.lower()

        # Direct name lookup
        if reg_name in regs:
            return regs[reg_name]

        # Check aliases
        if arch in ("aarch64", "arm64"):
            alias = AARCH64_ARG_ALIASES.get(reg_name)
            if alias and alias in regs:
                return regs[alias]
            if reg_name.startswith("v") and reg_name[1:].isdigit():
                num = reg_name[1:]
                for pfx in ("d", "s", "q"):
                    if f"{pfx}{num}" in regs:
                        return regs[f"{pfx}{num}"]
            elif (reg_name.startswith("d") or reg_name.startswith("s")) and reg_name[1:].isdigit():
                num = reg_name[1:]
                if f"v{num}" in regs:
                    return regs[f"v{num}"]
        else:
            alias = X86_64_ARG_ALIASES.get(reg_name)
            if alias and alias in regs:
                return regs[alias]

        # Check frame metadata
        if context.frame_metadata:
            fm = context.frame_metadata
            if reg_name in ("sp", "rsp") and fm.stack_pointer is not None:
                return fm.stack_pointer
            if reg_name in ("fp", "bp", "rbp", "x29") and fm.frame_pointer is not None:
                return fm.frame_pointer
            if reg_name in ("ra", "lr", "r30", "x30") and fm.return_address is not None:
                return fm.return_address
            if reg_name in ("pc", "ip", "rip") and fm.instruction_pointer is not None:
                return fm.instruction_pointer

        return None

    @classmethod
    def _evaluate_register_location(
        cls,
        context: DwarfEvaluationContext,
        var_name: str,
        reg_num: int,
        type_name: str,
        byte_size: int,
        canonical_type: Optional[DwarfType] = None,
    ) -> DwarfLocationResult:
        arch = context.architecture.lower()
        reg_name = cls._get_register_name(arch, reg_num)
        if not reg_name:
            return DwarfLocationResult(
                variable_name=var_name,
                status=EVAL_STATUS_UNSUPPORTED,
                type_name=type_name,
                byte_size=byte_size,
                reason=f"Unknown DWARF register number {reg_num} on {arch}",
            )

        reg_val = cls._lookup_register_value(context, reg_name)
        if reg_val is None:
            return DwarfLocationResult(
                variable_name=var_name,
                status=EVAL_STATUS_UNAVAILABLE,
                location_type="register",
                location_description=f"register:{reg_name}",
                register_name=reg_name,
                type_name=type_name,
                byte_size=byte_size,
                reason=f"Register '{reg_name}' not available in observation payload",
            )

        endianness = context.binary_identity.endianness if hasattr(context.binary_identity, "endianness") else "little"
        pointer_size = context.binary_identity.pointer_size if hasattr(context.binary_identity, "pointer_size") else 8

        val, val_hex = unpack_scalar_from_register(
            reg_val=reg_val,
            type_name=type_name,
            byte_size=byte_size,
            pointer_size=pointer_size,
            endianness=endianness or "little",
            canonical_type=canonical_type,
        )

        return DwarfLocationResult(
            variable_name=var_name,
            status=EVAL_STATUS_OBSERVED,
            location_type="register",
            location_description=f"register:{reg_name}",
            register_name=reg_name,
            value=val,
            value_hex=val_hex,
            type_name=type_name,
            byte_size=byte_size,
        )

    @classmethod
    def _evaluate_breg_location(
        cls,
        context: DwarfEvaluationContext,
        var_name: str,
        reg_num: int,
        offset: int,
        type_name: str,
        byte_size: int,
        canonical_type: Optional[DwarfType] = None,
    ) -> DwarfLocationResult:
        """Evaluate DW_OP_breg* <offset> (register + offset)."""
        arch = context.architecture.lower()
        reg_name = cls._get_register_name(arch, reg_num)
        if not reg_name:
            return DwarfLocationResult(
                variable_name=var_name,
                status=EVAL_STATUS_UNSUPPORTED,
                type_name=type_name,
                byte_size=byte_size,
                reason=f"Unknown DWARF register number {reg_num} on {arch}",
            )

        reg_val = cls._lookup_register_value(context, reg_name)
        if reg_val is None:
            return DwarfLocationResult(
                variable_name=var_name,
                status=EVAL_STATUS_UNAVAILABLE,
                location_type="memory",
                location_description=f"{reg_name}+{offset}",
                register_name=reg_name,
                type_name=type_name,
                byte_size=byte_size,
                reason=f"Register '{reg_name}' not available in observation payload",
            )

        target_addr = reg_val + offset
        loc_desc = f"memory:0x{target_addr:x} ({reg_name}{'+' if offset >= 0 else ''}{offset})"
        norm_target_addr = AddressValidator.normalize_data_address(target_addr, context.architecture)

        if norm_target_addr is None or not AddressValidator.is_valid_memory_address(
            norm_target_addr, byte_size, context.architecture
        ):
            return DwarfLocationResult(
                variable_name=var_name,
                status=EVAL_STATUS_UNAVAILABLE,
                location_type="memory",
                location_description=loc_desc,
                evaluated_address=target_addr,
                type_name=type_name,
                byte_size=byte_size,
                reason=f"Target address 0x{target_addr:x} is outside valid userspace memory bounds",
            )

        if context.memory_reader:
            try:
                mem_bytes = context.memory_reader(norm_target_addr, byte_size)
                if mem_bytes is not None and len(mem_bytes) >= byte_size:
                    endianness = context.binary_identity.endianness or "little"
                    val, val_hex = unpack_scalar_from_bytes(
                        raw_bytes=mem_bytes[:byte_size],
                        type_name=type_name,
                        endianness=endianness,
                        pointer_size=8,
                        canonical_type=canonical_type,
                    )
                    return DwarfLocationResult(
                        variable_name=var_name,
                        status=EVAL_STATUS_OBSERVED,
                        location_type="memory",
                        location_description=loc_desc,
                        evaluated_address=norm_target_addr,
                        value=val,
                        value_hex=val_hex,
                        type_name=type_name,
                        byte_size=byte_size,
                    )
                else:
                    return DwarfLocationResult(
                        variable_name=var_name,
                        status=EVAL_STATUS_UNAVAILABLE,
                        location_type="memory",
                        location_description=loc_desc,
                        evaluated_address=norm_target_addr,
                        type_name=type_name,
                        byte_size=byte_size,
                        reason=f"Failed to read memory at 0x{norm_target_addr:x} ({byte_size} bytes): memory unreadable",
                    )
            except Exception as e:
                return DwarfLocationResult(
                    variable_name=var_name,
                    status=EVAL_STATUS_UNAVAILABLE,
                    location_type="memory",
                    location_description=loc_desc,
                    evaluated_address=norm_target_addr,
                    type_name=type_name,
                    byte_size=byte_size,
                    reason=f"Failed to read memory at 0x{norm_target_addr:x}: {e}",
                )

        return DwarfLocationResult(
            variable_name=var_name,
            status=EVAL_STATUS_UNAVAILABLE,
            location_type="memory",
            location_description=loc_desc,
            evaluated_address=norm_target_addr,
            type_name=type_name,
            byte_size=byte_size,
            reason=f"Address 0x{norm_target_addr:x} evaluated successfully, but memory reader is not configured",
        )

    @classmethod
    def _evaluate_frame_base_location(
        cls,
        context: DwarfEvaluationContext,
        var_name: str,
        fb_offset: int,
        type_name: str,
        byte_size: int,
        canonical_type: Optional[DwarfType] = None,
    ) -> DwarfLocationResult:
        """Evaluate DW_OP_fbreg <offset> relative to subprogram DW_AT_frame_base / CFA."""
        arch = context.architecture.lower()
        subp = context.subprogram
        fm = context.frame_metadata

        # 1. Entry probe & prologue establishment check
        # When probe is at subprogram low_pc, prologue has not executed; stack variables do not exist yet.
        if subp and subp.low_pc is not None:
            if context.link_time_address == subp.low_pc:
                return DwarfLocationResult(
                    variable_name=var_name,
                    status=EVAL_STATUS_UNAVAILABLE,
                    location_type="stack_memory",
                    type_name=type_name,
                    byte_size=byte_size,
                    reason=(
                        f"Stack variable not accessible: observation point (0x{context.link_time_address:x}) "
                        f"is at function entry prior to prologue frame establishment"
                    ),
                )
            if subp.frame_established_pc is not None and context.link_time_address < subp.frame_established_pc:
                return DwarfLocationResult(
                    variable_name=var_name,
                    status=EVAL_STATUS_UNAVAILABLE,
                    location_type="stack_memory",
                    type_name=type_name,
                    byte_size=byte_size,
                    reason=(
                        f"Stack variable not accessible: observation point (0x{context.link_time_address:x}) "
                        f"is before prologue frame establishment (0x{subp.frame_established_pc:x})"
                    ),
                )

        # 2. Epilogue frame destruction check
        if subp and subp.frame_destroyed_pc is not None and context.link_time_address >= subp.frame_destroyed_pc:
            return DwarfLocationResult(
                variable_name=var_name,
                status=EVAL_STATUS_UNAVAILABLE,
                location_type="stack_memory",
                type_name=type_name,
                byte_size=byte_size,
                reason=(
                    f"Stack variable not accessible: observation point (0x{context.link_time_address:x}) "
                    f"is in function epilogue after frame destruction (0x{subp.frame_destroyed_pc:x})"
                ),
            )

        # 3. Determine frame base according to DW_AT_frame_base
        frame_base_expr = subp.frame_base if subp else None
        base_addr: Optional[int] = None
        base_desc = "CFA"

        if frame_base_expr == "DW_OP_call_frame_cfa":
            fp_val = None
            if fm and fm.frame_pointer is not None and fm.frame_pointer != 0:
                fp_val = fm.frame_pointer
            else:
                fp_reg_name = "x29" if arch in ("aarch64", "arm64") else "rbp"
                fp_val = cls._lookup_register_value(context, fp_reg_name)

            sp_val = None
            if fm and fm.stack_pointer is not None and fm.stack_pointer != 0:
                sp_val = fm.stack_pointer
            else:
                sp_reg_name = "sp" if arch in ("aarch64", "arm64") else "rsp"
                sp_val = cls._lookup_register_value(context, sp_reg_name)

            cfa_rule = subp.get_cfa_rule_at(context.link_time_address) if subp else None
            if cfa_rule:
                cfa_reg, cfa_off, fp_est = cfa_rule
                if cfa_reg == "sp":
                    if sp_val is not None:
                        base_addr = sp_val + cfa_off
                        base_desc = f"CFA(SP+{cfa_off})"
                    elif fp_val is not None and fp_est and subp and subp.fp_offset_from_cfa is not None:
                        fp_delta = -subp.fp_offset_from_cfa
                        base_addr = fp_val + fp_delta
                        base_desc = f"CFA(FP+{fp_delta})"
                    elif subp and subp.has_frame_pointer is False:
                        return DwarfLocationResult(
                            variable_name=var_name,
                            status=EVAL_STATUS_UNAVAILABLE,
                            location_type="stack_memory",
                            type_name=type_name,
                            byte_size=byte_size,
                            reason=(
                                "Cannot compute Canonical Frame Address (CFA): function compiled with "
                                "-fomit-frame-pointer (no frame pointer rule in CFI) without DWARF unwind unwinding"
                            ),
                        )
                    else:
                        return DwarfLocationResult(
                            variable_name=var_name,
                            status=EVAL_STATUS_UNAVAILABLE,
                            location_type="stack_memory",
                            type_name=type_name,
                            byte_size=byte_size,
                            reason="Stack pointer register not available in observation context to compute CFA",
                        )
                elif cfa_reg == "fp":
                    if fp_val is None:
                        return DwarfLocationResult(
                            variable_name=var_name,
                            status=EVAL_STATUS_UNAVAILABLE,
                            location_type="stack_memory",
                            type_name=type_name,
                            byte_size=byte_size,
                            reason="Frame pointer register not available in observation context",
                        )
                    base_addr = fp_val + cfa_off
                    base_desc = f"CFA(FP+{cfa_off})"
                else:
                    return DwarfLocationResult(
                        variable_name=var_name,
                        status=EVAL_STATUS_UNSUPPORTED,
                        location_type="stack_memory",
                        type_name=type_name,
                        byte_size=byte_size,
                        reason=f"Unsupported CFA base register '{cfa_reg}' in CFI rule",
                    )
            else:
                if subp and subp.has_frame_pointer is False:
                    return DwarfLocationResult(
                        variable_name=var_name,
                        status=EVAL_STATUS_UNAVAILABLE,
                        location_type="stack_memory",
                        type_name=type_name,
                        byte_size=byte_size,
                        reason=(
                            "Cannot compute Canonical Frame Address (CFA): function compiled with "
                            "-fomit-frame-pointer (no frame pointer rule in CFI) without DWARF unwind unwinding"
                        ),
                    )
                if fp_val is None:
                    return DwarfLocationResult(
                        variable_name=var_name,
                        status=EVAL_STATUS_UNAVAILABLE,
                        location_type="stack_memory",
                        type_name=type_name,
                        byte_size=byte_size,
                        reason="Frame pointer register not available in observation context",
                    )
                base_addr = fp_val + (16 if arch in ("aarch64", "arm64", "x86_64") else 8)
                base_desc = "CFA"

        elif frame_base_expr in ("DW_OP_reg6", "DW_OP_reg29"):
            # Direct frame register
            reg_name = "x29" if arch in ("aarch64", "arm64") else "rbp"
            reg_val = cls._lookup_register_value(context, reg_name)
            if reg_val is None:
                return DwarfLocationResult(
                    variable_name=var_name,
                    status=EVAL_STATUS_UNAVAILABLE,
                    location_type="stack_memory",
                    type_name=type_name,
                    byte_size=byte_size,
                    reason=f"Frame register '{reg_name}' not available in observation context",
                )
            base_addr = reg_val
            base_desc = reg_name

        elif frame_base_expr and ("DW_OP_reg" in frame_base_expr):
            m_reg = re.search(r"DW_OP_reg(\d+)", frame_base_expr)
            if m_reg:
                r_num = int(m_reg.group(1))
                r_name = cls._get_register_name(arch, r_num)
                if r_name:
                    r_val = cls._lookup_register_value(context, r_name)
                    if r_val is not None:
                        base_addr = r_val
                        base_desc = r_name
            if base_addr is None:
                return DwarfLocationResult(
                    variable_name=var_name,
                    status=EVAL_STATUS_UNAVAILABLE,
                    location_type="stack_memory",
                    type_name=type_name,
                    byte_size=byte_size,
                    reason=f"Frame base register for '{frame_base_expr}' unavailable",
                )
        else:
            return DwarfLocationResult(
                variable_name=var_name,
                status=EVAL_STATUS_UNSUPPORTED,
                location_type="stack_memory",
                type_name=type_name,
                byte_size=byte_size,
                reason=f"Unsupported DW_AT_frame_base expression: '{frame_base_expr}'",
            )

        var_addr = base_addr + fb_offset
        loc_desc = f"stack:0x{var_addr:x} ({base_desc}{'+' if fb_offset >= 0 else ''}{fb_offset})"
        norm_var_addr = AddressValidator.normalize_data_address(var_addr, context.architecture)

        if norm_var_addr is None or not AddressValidator.is_valid_memory_address(
            norm_var_addr, byte_size, context.architecture
        ):
            return DwarfLocationResult(
                variable_name=var_name,
                status=EVAL_STATUS_UNAVAILABLE,
                location_type="stack_memory",
                location_description=loc_desc,
                evaluated_address=var_addr,
                type_name=type_name,
                byte_size=byte_size,
                reason=f"Stack address 0x{var_addr:x} is outside valid userspace memory bounds",
            )

        # If a memory reader is provided, read and unpack the value
        if context.memory_reader:
            try:
                mem_bytes = context.memory_reader(norm_var_addr, byte_size)
                if mem_bytes is not None and len(mem_bytes) >= byte_size:
                    endianness = context.binary_identity.endianness or "little"
                    val, val_hex = unpack_scalar_from_bytes(
                        raw_bytes=mem_bytes[:byte_size],
                        type_name=type_name,
                        endianness=endianness,
                        pointer_size=8,
                        canonical_type=canonical_type,
                    )
                    return DwarfLocationResult(
                        variable_name=var_name,
                        status=EVAL_STATUS_OBSERVED,
                        location_type="stack_memory",
                        location_description=loc_desc,
                        evaluated_address=norm_var_addr,
                        value=val,
                        value_hex=val_hex,
                        type_name=type_name,
                        byte_size=byte_size,
                    )
                else:
                    return DwarfLocationResult(
                        variable_name=var_name,
                        status=EVAL_STATUS_UNAVAILABLE,
                        location_type="stack_memory",
                        location_description=loc_desc,
                        evaluated_address=norm_var_addr,
                        type_name=type_name,
                        byte_size=byte_size,
                        reason=f"Failed to read stack memory at 0x{norm_var_addr:x} ({byte_size} bytes): memory unreadable",
                    )
            except Exception as e:
                return DwarfLocationResult(
                    variable_name=var_name,
                    status=EVAL_STATUS_UNAVAILABLE,
                    location_type="stack_memory",
                    location_description=loc_desc,
                    evaluated_address=norm_var_addr,
                    type_name=type_name,
                    byte_size=byte_size,
                    reason=f"Failed to read stack memory at 0x{norm_var_addr:x}: {e}",
                )

        # Memory reader not available: truthful reporting of evaluated address without fabricating value
        return DwarfLocationResult(
            variable_name=var_name,
            status=EVAL_STATUS_UNAVAILABLE,
            location_type="stack_memory",
            location_description=loc_desc,
            evaluated_address=norm_var_addr,
            type_name=type_name,
            byte_size=byte_size,
            reason=f"Stack address 0x{norm_var_addr:x} evaluated successfully, but memory reader is not configured",
        )


# -----------------------------------------------------------------------------
# Phase 2 Implementation of DwarfLocationResolverInterface
# -----------------------------------------------------------------------------

class Phase2DwarfLocationResolver(DwarfLocationResolverInterface):
    """Phase 2 DWARF location resolver integrating DwarfEvaluator into trace events."""

    def __init__(
        self,
        binary_identity: BinaryIdentity,
        link_time_address: Optional[int] = None,
        load_bias: int = 0,
        architecture: str = "x86_64",
        memory_reader: Optional[Callable[[int, int], Optional[bytes]]] = None,
        debug_artifact_path: Optional[str] = None,
    ):
        self.binary_identity = binary_identity
        self.link_time_address = link_time_address
        self.load_bias = load_bias
        self.architecture = architecture
        self.memory_reader = memory_reader
        self.debug_artifact_path = debug_artifact_path

    def resolve_variable(
        self,
        subprogram: Optional[DwarfSubprogram],
        variable_name: str,
        registers: Dict[str, int],
        frame_metadata: FrameMetadata,
    ) -> TraceValue:
        effective_link_pc = (
            frame_metadata.link_time_address
            if (frame_metadata and frame_metadata.link_time_address is not None)
            else self.link_time_address
        )
        context = DwarfEvaluationContext(
            binary_identity=self.binary_identity,
            subprogram=subprogram,
            link_time_address=effective_link_pc,
            load_bias=self.load_bias,
            registers=registers,
            frame_metadata=frame_metadata,
            variable_name=variable_name,
            architecture=self.architecture,
            memory_reader=self.memory_reader,
            debug_artifact_path=self.debug_artifact_path,
        )
        res = DwarfEvaluator.evaluate(context)
        return res.to_trace_value()

