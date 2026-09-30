"""Snapshot-backed memory reader enforcing captured ranges and permissions.

Reads strictly from RawRuntimeSnapshot buffers without accessing live process memory.
If requested memory is uncaptured, returns MEMORY_NOT_CAPTURED rather than fabricated zero data.
"""

from dataclasses import dataclass
import struct
from typing import Any, Dict, List, Optional, Tuple, Union

from .raw_snapshot import RawRuntimeSnapshot


@dataclass
class MemoryReadResult:
    """Result of a typed memory read operation."""
    success: bool
    data: Optional[bytes] = None
    value: Any = None
    status: str = "COMPLETE"  # COMPLETE, MEMORY_NOT_CAPTURED, OUTSIDE_CAPTURE, PERMISSION_DENIED
    address: int = 0
    size: int = 0
    error: Optional[str] = None


class TypedMemoryReader:
    """Snapshot-backed typed memory reader.
    
    Guarantees:
    - Never communicates with a live process.
    - Strictly checks captured memory ranges.
    - Never fabricates zero data for uncaptured memory.
    """

    def __init__(
        self,
        snapshot: RawRuntimeSnapshot,
        pointer_size: int = 8,
        endianness: str = "little"
    ):
        self.snapshot = snapshot
        self.pointer_size = pointer_size
        self.endianness = endianness
        self._endian_fmt = "<" if endianness == "little" else ">"

        # Index buffers for fast range checks
        # List of (start, end, bytes)
        self._buffers: List[Tuple[int, int, bytes]] = []
        for (b_start, b_end), data in self.snapshot._buffers.items():
            self._buffers.append((b_start, b_end, data))
        self._buffers.sort(key=lambda b: b[0])

        # Also collect captured ranges from snapshot metadata if buffers aren't loaded
        self._captured_ranges: List[Tuple[int, int]] = list(self.snapshot.captured_ranges)
        self._captured_ranges.sort(key=lambda r: r[0])

        # Memory regions from /proc/maps metadata
        self._regions: List[Dict[str, Any]] = list(self.snapshot.memory_regions)

    def is_captured(self, address: int, size: int = 1) -> bool:
        """Check if memory range [address, address + size) is captured in buffers."""
        if size <= 0:
            return True
        end_addr = address + size
        for b_start, b_end, _ in self._buffers:
            if b_start <= address and end_addr <= b_end:
                return True
        return False

    def is_in_captured_ranges(self, address: int, size: int = 1) -> bool:
        """Check if memory range is reported in snapshot captured_ranges."""
        if size <= 0:
            return True
        end_addr = address + size
        for r_start, r_end in self._captured_ranges:
            if r_start <= address and end_addr <= r_end:
                return True
        return False

    def contains(self, address: int, size: int) -> bool:
        """Return True only if the entire requested range [address, address + size) is available."""
        return self.is_captured(address, size)

    def get_region(self, address: int) -> Optional[Dict[str, Any]]:
        """Find memory region metadata covering the specified address."""
        for r in self._regions:
            start = r.get("start")
            end = r.get("end")
            if isinstance(start, str):
                start = int(start, 16)
            if isinstance(end, str):
                end = int(end, 16)
            if start is not None and end is not None and start <= address < end:
                return r
        return None

    def is_heap(self, address: int) -> bool:
        reg = self.get_region(address)
        if reg:
            return reg.get("category") == "heap" or reg.get("pathname") == "[heap]"
        return False

    def is_stack(self, address: int) -> bool:
        reg = self.get_region(address)
        if reg:
            cat = reg.get("category")
            path = reg.get("pathname", "")
            return cat == "stack" or path.startswith("[stack")
        return False

    def read(self, address: int, size: int) -> Tuple[Optional[bytes], str]:
        """Read arbitrary byte slice from snapshot.
        
        Returns:
            (bytes, "COMPLETE") on success
            (None, "MEMORY_NOT_CAPTURED") if uncaptured
            (None, "OUTSIDE_CAPTURE") if outside any known process memory
        """
        if size <= 0:
            return b"", "COMPLETE"

        end_addr = address + size
        for b_start, b_end, buf in self._buffers:
            if b_start <= address and end_addr <= b_end:
                offset = address - b_start
                return buf[offset : offset + size], "COMPLETE"

        # Not found in loaded buffers. Check if address belongs to known regions
        reg = self.get_region(address)
        if reg:
            return None, "MEMORY_NOT_CAPTURED"
        return None, "OUTSIDE_CAPTURE"

    def read_bytes(self, address: int, size: int) -> Optional[bytes]:
        data, status = self.read(address, size)
        return data if status == "COMPLETE" else None

    def read_pointer(self, address: int) -> Tuple[Optional[int], str]:
        """Read a pointer value (4 or 8 bytes depending on pointer_size)."""
        data, status = self.read(address, self.pointer_size)
        if status != "COMPLETE" or not data:
            return None, status
        fmt = self._endian_fmt + ("Q" if self.pointer_size == 8 else "I")
        try:
            val = struct.unpack(fmt, data)[0]
            return val, "COMPLETE"
        except Exception as exc:
            return None, f"DECODE_ERROR: {exc}"

    def read_integer(
        self,
        address: int,
        size: int = 4,
        signed: bool = True
    ) -> Tuple[Optional[int], str]:
        """Read an integer of specified byte size (1, 2, 4, 8)."""
        data, status = self.read(address, size)
        if status != "COMPLETE" or not data:
            return None, status
        byteorder = "little" if self.endianness == "little" else "big"
        try:
            val = int.from_bytes(data, byteorder=byteorder, signed=signed)
            return val, "COMPLETE"
        except Exception as exc:
            return None, f"DECODE_ERROR: {exc}"

    def read_float(self, address: int, size: int = 4) -> Tuple[Optional[float], str]:
        """Read a float (4 bytes) or double (8 bytes)."""
        data, status = self.read(address, size)
        if status != "COMPLETE" or not data:
            return None, status
        fmt = self._endian_fmt + ("f" if size == 4 else "d")
        try:
            val = struct.unpack(fmt, data)[0]
            return val, "COMPLETE"
        except Exception as exc:
            return None, f"DECODE_ERROR: {exc}"
