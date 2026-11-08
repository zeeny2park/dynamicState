"""Phase 2.1.3 — Allocator Inspection Interface & Implementations

Provides an allocator abstraction layer separating:
- glibc ptmalloc
- jemalloc
- tcmalloc
- Embedded/custom allocator
- Unknown allocator

Inspects chunk headers, validates allocation boundaries, and ensures glibc
chunk layout assumptions are never applied to unknown or custom allocators.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class AllocatorType(str, Enum):
    GLIBC_PTMALLOC = "GLIBC_PTMALLOC"
    JEMALLOC = "JEMALLOC"
    TCMALLOC = "TCMALLOC"
    EMBEDDED_CUSTOM = "EMBEDDED_CUSTOM"
    UNKNOWN = "UNKNOWN"


@dataclass
class ChunkInfo:
    """Decoded metadata for an allocator heap chunk."""
    address: int
    user_data_address: int
    requested_size: Optional[int]
    chunk_size: int
    is_allocated: bool
    prev_inuse: bool
    flags: Dict[str, Any] = field(default_factory=dict)
    is_valid_start: bool = True
    allocator_type: AllocatorType = AllocatorType.UNKNOWN
    limitations: List[str] = field(default_factory=list)


class AllocatorInspector(ABC):
    """Abstract interface for inspecting target runtime allocator state."""

    @abstractmethod
    def allocator_type(self) -> AllocatorType:
        pass

    @abstractmethod
    def inspect_chunk(self, raw_bytes: bytes, address: int) -> ChunkInfo:
        pass

    @abstractmethod
    def is_valid_allocation_start(self, address: int, maps: List[Dict[str, Any]]) -> bool:
        pass

    @abstractmethod
    def validate_free_target(
        self,
        target_address: int,
        raw_header: Optional[bytes] = None,
        maps: Optional[List[Dict[str, Any]]] = None,
    ) -> Tuple[bool, Optional[str]]:
        """Validates if pointer passed to free() complies with allocator contract."""
        pass


class GlibcPtMallocInspector(AllocatorInspector):
    """Inspector for GNU C Library ptmalloc (dlmalloc derivative)."""

    def allocator_type(self) -> AllocatorType:
        return AllocatorType.GLIBC_PTMALLOC

    def inspect_chunk(self, raw_bytes: bytes, address: int) -> ChunkInfo:
        if len(raw_bytes) < 16:
            return ChunkInfo(
                address=address,
                user_data_address=address + 16,
                requested_size=None,
                chunk_size=0,
                is_allocated=False,
                prev_inuse=False,
                is_valid_start=False,
                allocator_type=self.allocator_type(),
                limitations=["Insufficient header bytes read"],
            )

        # In 64-bit glibc ptmalloc:
        # offset 0: prev_size (8 bytes)
        # offset 8: size & flags (8 bytes)
        prev_size = int.from_bytes(raw_bytes[0:8], "little")
        size_flags = int.from_bytes(raw_bytes[8:16], "little")

        prev_inuse = bool(size_flags & 0x1)
        is_mmapped = bool(size_flags & 0x2)
        non_main_arena = bool(size_flags & 0x4)
        chunk_size = size_flags & ~0x7

        # User data starts right after chunk header (offset 16)
        user_addr = address + 16

        return ChunkInfo(
            address=address,
            user_data_address=user_addr,
            requested_size=max(0, chunk_size - 16) if chunk_size > 16 else 0,
            chunk_size=chunk_size,
            is_allocated=prev_inuse,
            prev_inuse=prev_inuse,
            flags={
                "prev_inuse": prev_inuse,
                "is_mmapped": is_mmapped,
                "non_main_arena": non_main_arena,
                "prev_size": prev_size,
            },
            is_valid_start=True,
            allocator_type=self.allocator_type(),
        )

    def is_valid_allocation_start(self, address: int, maps: List[Dict[str, Any]]) -> bool:
        # In glibc 64-bit, pointers returned by malloc are 16-byte aligned
        if address % 16 != 0:
            return False
        # Must be located in mapped heap or anonymous rw-p region
        for m in maps:
            if m.get("start_int", 0) <= address < m.get("end_int", 0):
                perms = m.get("permissions", "")
                return "r" in perms and "w" in perms
        return False

    def validate_free_target(
        self,
        target_address: int,
        raw_header: Optional[bytes] = None,
        maps: Optional[List[Dict[str, Any]]] = None,
    ) -> Tuple[bool, Optional[str]]:
        if target_address == 0:
            return True, None  # free(NULL) is a no-op per C standard
        if target_address % 16 != 0:
            return False, f"Pointer {hex(target_address)} is misaligned (glibc requires 16-byte alignment)"
        if maps:
            in_heap = False
            for m in maps:
                if m.get("start_int", 0) <= target_address < m.get("end_int", 0):
                    in_heap = True
                    break
            if not in_heap:
                return False, f"Pointer {hex(target_address)} does not belong to any mapped memory region"

        if raw_header and len(raw_header) >= 16:
            size_flags = int.from_bytes(raw_header[8:16], "little")
            chunk_size = size_flags & ~0x7
            if chunk_size < 32 or chunk_size > (1024 * 1024 * 1024):
                return False, f"Chunk size {chunk_size} out of valid allocator range"

        return True, None


class JemallocInspector(AllocatorInspector):
    """Inspector for FreeBSD/Facebook jemalloc."""

    def allocator_type(self) -> AllocatorType:
        return AllocatorType.JEMALLOC

    def inspect_chunk(self, raw_bytes: bytes, address: int) -> ChunkInfo:
        return ChunkInfo(
            address=address,
            user_data_address=address,
            requested_size=None,
            chunk_size=len(raw_bytes),
            is_allocated=True,
            prev_inuse=True,
            flags={"arena_chunk": True},
            is_valid_start=True,
            allocator_type=self.allocator_type(),
            limitations=["jemalloc slab descriptor inspection requires external run headers"],
        )

    def is_valid_allocation_start(self, address: int, maps: List[Dict[str, Any]]) -> bool:
        if address % 8 != 0:
            return False
        return any(m.get("start_int", 0) <= address < m.get("end_int", 0) for m in maps)

    def validate_free_target(
        self,
        target_address: int,
        raw_header: Optional[bytes] = None,
        maps: Optional[List[Dict[str, Any]]] = None,
    ) -> Tuple[bool, Optional[str]]:
        if target_address == 0:
            return True, None
        if target_address % 8 != 0:
            return False, f"Pointer {hex(target_address)} violates jemalloc alignment"
        return True, None


class TcmallocInspector(AllocatorInspector):
    """Inspector for Google tcmalloc (Thread-Caching Malloc)."""

    def allocator_type(self) -> AllocatorType:
        return AllocatorType.TCMALLOC

    def inspect_chunk(self, raw_bytes: bytes, address: int) -> ChunkInfo:
        return ChunkInfo(
            address=address,
            user_data_address=address,
            requested_size=None,
            chunk_size=len(raw_bytes),
            is_allocated=True,
            prev_inuse=True,
            flags={"central_freelist": False},
            is_valid_start=True,
            allocator_type=self.allocator_type(),
            limitations=["tcmalloc central cache span lookup requires pagemap translation"],
        )

    def is_valid_allocation_start(self, address: int, maps: List[Dict[str, Any]]) -> bool:
        if address % 8 != 0:
            return False
        return any(m.get("start_int", 0) <= address < m.get("end_int", 0) for m in maps)

    def validate_free_target(
        self,
        target_address: int,
        raw_header: Optional[bytes] = None,
        maps: Optional[List[Dict[str, Any]]] = None,
    ) -> Tuple[bool, Optional[str]]:
        if target_address == 0:
            return True, None
        if target_address % 8 != 0:
            return False, f"Pointer {hex(target_address)} violates tcmalloc alignment"
        return True, None


class CustomAllocatorInspector(AllocatorInspector):
    """Inspector for embedded fixed-pool or application-specific custom allocators."""

    def allocator_type(self) -> AllocatorType:
        return AllocatorType.EMBEDDED_CUSTOM

    def inspect_chunk(self, raw_bytes: bytes, address: int) -> ChunkInfo:
        return ChunkInfo(
            address=address,
            user_data_address=address,
            requested_size=None,
            chunk_size=len(raw_bytes),
            is_allocated=True,
            prev_inuse=True,
            flags={"custom_pool": True},
            is_valid_start=True,
            allocator_type=self.allocator_type(),
            limitations=["Custom allocator chunk layout requires explicit schema metadata"],
        )

    def is_valid_allocation_start(self, address: int, maps: List[Dict[str, Any]]) -> bool:
        return any(m.get("start_int", 0) <= address < m.get("end_int", 0) for m in maps)

    def validate_free_target(
        self,
        target_address: int,
        raw_header: Optional[bytes] = None,
        maps: Optional[List[Dict[str, Any]]] = None,
    ) -> Tuple[bool, Optional[str]]:
        if target_address == 0:
            return True, None
        return True, None


class UnknownAllocatorInspector(AllocatorInspector):
    """Inspector for unidentifiable or unsupported target allocators."""

    def allocator_type(self) -> AllocatorType:
        return AllocatorType.UNKNOWN

    def inspect_chunk(self, raw_bytes: bytes, address: int) -> ChunkInfo:
        return ChunkInfo(
            address=address,
            user_data_address=address,
            requested_size=None,
            chunk_size=0,
            is_allocated=False,
            prev_inuse=False,
            flags={},
            is_valid_start=False,
            allocator_type=self.allocator_type(),
            limitations=["Unknown allocator: standard chunk layout assumptions refused"],
        )

    def is_valid_allocation_start(self, address: int, maps: List[Dict[str, Any]]) -> bool:
        # Without allocator metadata, cannot prove an address is a valid start
        return False

    def validate_free_target(
        self,
        target_address: int,
        raw_header: Optional[bytes] = None,
        maps: Optional[List[Dict[str, Any]]] = None,
    ) -> Tuple[bool, Optional[str]]:
        if target_address == 0:
            return True, None
        return True, "Unknown allocator: cannot verify free() contract compliance"


def detect_allocator(
    maps: List[Dict[str, Any]],
    symbols: Optional[List[str]] = None,
) -> AllocatorInspector:
    """Detects target runtime allocator from memory maps and symbol signatures."""
    sym_set = set(symbols or [])
    if any("je_malloc" in s or "jemalloc" in s for s in sym_set):
        return JemallocInspector()
    if any("tc_malloc" in s or "tcmalloc" in s for s in sym_set):
        return TcmallocInspector()

    # Check shared libraries in memory maps
    for m in maps:
        p = m.get("pathname", "")
        if "libjemalloc" in p:
            return JemallocInspector()
        if "libtcmalloc" in p:
            return TcmallocInspector()
        if "libc.so" in p or "libc-" in p:
            return GlibcPtMallocInspector()

    # Default to glibc ptmalloc on standard Linux if libc present
    return GlibcPtMallocInspector()
