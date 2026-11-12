"""Phase 2.1.4 — Allocator Inspection Interface & Implementations

Provides an allocator abstraction layer separating:
- glibc ptmalloc (dlmalloc derivative)
- jemalloc
- tcmalloc
- Embedded/custom allocator
- Unknown allocator

Enforces strict allocator semantics:
- PREV_INUSE describes the previous physical chunk, never the current chunk's allocation state.
- Current chunk allocation status requires the NEXT physical chunk's PREV_INUSE bit or mmap flag.
- Distinguishes chunk header address from user pointer address (ptr = chunk + 2*SIZE_SZ).
- Validates chunk alignment, minimum size, and boundaries.
- jemalloc / tcmalloc / custom allocators never report is_allocated=True merely because memory is mapped.
- Unknown allocators never default to glibc assumptions.
- Allocator detection distinguishes CONFIRMED, PROBABLE, and UNKNOWN identification.
- free() target validation classifies specific contract violations.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple, Union, NamedTuple


class AllocatorType(str, Enum):
    GLIBC_PTMALLOC = "GLIBC_PTMALLOC"
    JEMALLOC = "JEMALLOC"
    TCMALLOC = "TCMALLOC"
    EMBEDDED_CUSTOM = "EMBEDDED_CUSTOM"
    UNKNOWN = "UNKNOWN"


class PointerClassification(str, Enum):
    MAPPED_READABLE = "MAPPED_READABLE"
    ALLOCATED_OBJECT = "ALLOCATED_OBJECT"
    FREED_CHUNK = "FREED_CHUNK"
    INTERIOR_POINTER = "INTERIOR_POINTER"
    OUT_OF_RANGE = "OUT_OF_RANGE"
    UNKNOWN = "UNKNOWN"


@dataclass
class PointerClassificationResult:
    """Evidence-based pointer classification result."""
    address: int
    classification: PointerClassification
    is_valid_pointer: bool
    vma_permissions: Optional[str] = None
    vma_pathname: Optional[str] = None
    allocator_type: AllocatorType = AllocatorType.UNKNOWN
    reason: Optional[str] = None
    chunk_address: Optional[int] = None
    user_ptr: Optional[int] = None
    chunk_size: Optional[int] = None
    limitations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["classification"] = self.classification.value
        d["allocator_type"] = self.allocator_type.value if hasattr(self.allocator_type, "value") else str(self.allocator_type)
        return d


class FreeValidationOutcome(str, Enum):
    VALID = "VALID"
    FREE_TARGET_NULL = "FREE_TARGET_NULL"
    FREE_TARGET_MISALIGNED = "FREE_TARGET_MISALIGNED"
    FREE_TARGET_OUTSIDE_HEAP = "FREE_TARGET_OUTSIDE_HEAP"
    FREE_TARGET_INTERIOR_POINTER = "FREE_TARGET_INTERIOR_POINTER"
    FREE_TARGET_INVALID_BOUNDARY = "FREE_TARGET_INVALID_BOUNDARY"
    FREE_TARGET_ALREADY_RELEASED = "FREE_TARGET_ALREADY_RELEASED"
    FREE_TARGET_DOUBLE_FREE = "FREE_TARGET_DOUBLE_FREE"
    FREE_TARGET_UNKNOWN_ALLOCATOR = "FREE_TARGET_UNKNOWN_ALLOCATOR"


class FreeValidationResult(NamedTuple):
    is_valid: bool
    outcome: FreeValidationOutcome
    reason: Optional[str]


@dataclass
class ChunkInfo:
    """Decoded metadata for an allocator heap chunk."""
    address: int  # Chunk header address
    user_data_address: int  # User pointer address returned by malloc()
    requested_size: Optional[int]
    chunk_size: int
    is_allocated: Optional[bool]  # None if indeterminate/unproven from local header
    prev_inuse: bool  # Describes PREVIOUS physical chunk only
    is_mmapped: bool = False
    allocation_state_proven: bool = False  # True only if authoritatively established
    flags: Dict[str, Any] = field(default_factory=dict)
    is_valid_start: Optional[bool] = None  # None if cannot be verified
    allocator_type: AllocatorType = AllocatorType.UNKNOWN
    limitations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["allocator_type"] = self.allocator_type.value
        return d


@dataclass
class AllocatorDetectionResult:
    """Result of detecting runtime allocator from process maps and symbols."""
    inspector: "AllocatorInspector"
    confidence: str  # "CONFIRMED", "PROBABLE", "UNKNOWN"
    basis: str
    limitations: List[str] = field(default_factory=list)
    # IMP-015: target-ABI support decision when the caller supplied the detected target ABI
    # (None: ABI not consulted; "SUPPORTED" / "NOT_SUPPORTED_ON_TARGET" / "INCONCLUSIVE_ABI_UNDETECTED").
    support_status: Optional[str] = None

    @property
    def allocator_type(self) -> AllocatorType:
        return self.inspector.allocator_type()


class AllocatorInspector(ABC):
    """Abstract interface for inspecting target runtime allocator state."""

    @abstractmethod
    def allocator_type(self) -> AllocatorType:
        pass

    @abstractmethod
    def inspect_chunk(
        self,
        raw_bytes: bytes,
        address: int,
        next_chunk_raw: Optional[bytes] = None,
        is_user_ptr: bool = False,
    ) -> ChunkInfo:
        pass

    @abstractmethod
    def is_valid_allocation_start(self, address: int, maps: List[Dict[str, Any]]) -> Optional[bool]:
        pass

    @abstractmethod
    def validate_free_target(
        self,
        target_address: int,
        raw_header: Optional[bytes] = None,
        next_chunk_raw: Optional[bytes] = None,
        maps: Optional[List[Dict[str, Any]]] = None,
        freelist_records: Optional[List[Any]] = None,
    ) -> FreeValidationResult:
        """Validates if pointer passed to free() complies with allocator contract."""
        pass


class GlibcPtMallocInspector(AllocatorInspector):
    """Inspector for GNU C Library ptmalloc (dlmalloc derivative)."""

    def __init__(self, arch_bits: int = 64):
        self.arch_bits = arch_bits
        self.size_sz = arch_bits // 8  # 8 bytes on 64-bit, 4 bytes on 32-bit
        self.malloc_alignment = 2 * self.size_sz  # 16 bytes on 64-bit, 8 bytes on 32-bit
        self.min_chunk_size = 4 * self.size_sz  # 32 bytes on 64-bit, 16 bytes on 32-bit

    def allocator_type(self) -> AllocatorType:
        return AllocatorType.GLIBC_PTMALLOC

    def chunk_to_user_ptr(self, chunk_address: int) -> int:
        return chunk_address + 2 * self.size_sz

    def user_ptr_to_chunk(self, user_ptr: int) -> int:
        return user_ptr - 2 * self.size_sz

    def inspect_chunk(
        self,
        raw_bytes: bytes,
        address: int,
        next_chunk_raw: Optional[bytes] = None,
        is_user_ptr: bool = False,
    ) -> ChunkInfo:
        header_size = 2 * self.size_sz
        limitations: List[str] = []

        # If input address is a user pointer (as returned by malloc), chunk header precedes it
        if is_user_ptr:
            chunk_header_addr = address - header_size
            user_data_addr = address
        else:
            chunk_header_addr = address
            user_data_addr = address + header_size

        if len(raw_bytes) < header_size:
            return ChunkInfo(
                address=chunk_header_addr,
                user_data_address=user_data_addr,
                requested_size=None,
                chunk_size=0,
                is_allocated=None,
                prev_inuse=False,
                is_valid_start=False,
                allocation_state_proven=False,
                allocator_type=self.allocator_type(),
                limitations=["Insufficient header bytes read for glibc chunk metadata"],
            )

        # Parse prev_size and size_flags
        if self.arch_bits == 64:
            prev_size = int.from_bytes(raw_bytes[0:8], "little")
            size_flags = int.from_bytes(raw_bytes[8:16], "little")
        else:
            prev_size = int.from_bytes(raw_bytes[0:4], "little")
            size_flags = int.from_bytes(raw_bytes[4:8], "little")

        # Standard glibc flags:
        # bit 0: PREV_INUSE (0x1) — describes PREVIOUS physical chunk, NOT this chunk!
        # bit 1: IS_MMAPPED (0x2) — chunk allocated via mmap()
        # bit 2: NON_MAIN_ARENA (0x4) — chunk comes from secondary arena heap
        prev_inuse = bool(size_flags & 0x1)
        is_mmapped = bool(size_flags & 0x2)
        non_main_arena = bool(size_flags & 0x4)
        mask = ~(self.malloc_alignment - 1) & 0xFFFFFFFFFFFFFFFF
        chunk_size = size_flags & mask

        # Validate chunk boundary and minimum size
        is_valid_start = True
        if chunk_size < self.min_chunk_size and not is_mmapped:
            is_valid_start = False
            limitations.append(f"Chunk size {chunk_size} is smaller than glibc minimum ({self.min_chunk_size}B)")
        elif chunk_size % self.malloc_alignment != 0 and not is_mmapped:
            is_valid_start = False
            limitations.append(f"Chunk size {chunk_size} is not aligned to glibc quantum ({self.malloc_alignment}B)")

        # P0: Determine current chunk allocation state correctly
        # PREV_INUSE describes the previous chunk! Never derive this chunk's status from PREV_INUSE!
        is_allocated: Optional[bool] = None
        allocation_state_proven = False

        if is_mmapped:
            # mmap chunks are allocated until munmap()
            is_allocated = True
            allocation_state_proven = True
        elif next_chunk_raw and len(next_chunk_raw) >= header_size:
            # Current chunk's allocation status is stored in the NEXT chunk's PREV_INUSE bit!
            if self.arch_bits == 64:
                next_prev_size = int.from_bytes(next_chunk_raw[0:8], "little")
                next_size_flags = int.from_bytes(next_chunk_raw[8:16], "little")
            else:
                next_prev_size = int.from_bytes(next_chunk_raw[0:4], "little")
                next_size_flags = int.from_bytes(next_chunk_raw[4:8], "little")

            next_prev_inuse = bool(next_size_flags & 0x1)
            is_allocated = next_prev_inuse
            allocation_state_proven = True

            # If current chunk is free, next chunk's prev_size must equal current chunk_size
            if not next_prev_inuse and next_prev_size != chunk_size:
                is_valid_start = False
                limitations.append(
                    f"Chunk size mismatch: current chunk size ({chunk_size}) != next chunk prev_size ({next_prev_size})"
                )
        else:
            # Cannot determine current chunk's allocation state from current chunk's PREV_INUSE alone!
            is_allocated = None
            allocation_state_proven = False
            limitations.append(
                "PREV_INUSE describes previous physical chunk only. Current chunk allocation state requires next chunk's PREV_INUSE bit."
            )

        return ChunkInfo(
            address=chunk_header_addr,
            user_data_address=user_data_addr,
            requested_size=max(0, chunk_size - header_size) if chunk_size >= header_size else 0,
            chunk_size=chunk_size,
            is_allocated=is_allocated,
            prev_inuse=prev_inuse,
            is_mmapped=is_mmapped,
            allocation_state_proven=allocation_state_proven,
            flags={
                "prev_inuse": prev_inuse,
                "is_mmapped": is_mmapped,
                "non_main_arena": non_main_arena,
                "prev_size": prev_size,
            },
            is_valid_start=is_valid_start,
            allocator_type=self.allocator_type(),
            limitations=limitations,
        )

    def is_valid_allocation_start(self, address: int, maps: List[Dict[str, Any]]) -> Optional[bool]:
        # User pointer returned by malloc must satisfy malloc_alignment
        if address % self.malloc_alignment != 0:
            return False
        # Must be located in mapped writable region
        in_region = False
        for m in maps:
            start = m.get("start_int") if m.get("start_int") is not None else m.get("start", 0)
            end = m.get("end_int") if m.get("end_int") is not None else m.get("end", 0)
            if start <= address < end:
                perms = m.get("permissions") or m.get("perms", "")
                in_region = ("r" in perms and "w" in perms)
                break
        return in_region

    def validate_free_target(
        self,
        target_address: int,
        raw_header: Optional[bytes] = None,
        next_chunk_raw: Optional[bytes] = None,
        maps: Optional[List[Dict[str, Any]]] = None,
        freelist_records: Optional[List[Any]] = None,
    ) -> FreeValidationResult:
        if target_address == 0:
            return FreeValidationResult(True, FreeValidationOutcome.FREE_TARGET_NULL, "free(NULL) is standard no-op")

        # Check alignment of user pointer
        if target_address % self.malloc_alignment != 0:
            return FreeValidationResult(
                False,
                FreeValidationOutcome.FREE_TARGET_MISALIGNED,
                f"Pointer {hex(target_address)} violates glibc alignment ({self.malloc_alignment} bytes)",
            )

        # Check if pointer is outside mapped heap/mmap regions
        if maps:
            in_heap = False
            for m in maps:
                start = m.get("start_int") if m.get("start_int") is not None else m.get("start", 0)
                end = m.get("end_int") if m.get("end_int") is not None else m.get("end", 0)
                if start <= target_address < end:
                    perms = m.get("permissions") or m.get("perms", "")
                    pname = (m.get("pathname") or m.get("name") or "").strip()
                    cat = (m.get("category") or "").strip().lower()
                    if "[stack" in pname.lower() or cat == "stack":
                        return FreeValidationResult(
                            False,
                            FreeValidationOutcome.FREE_TARGET_OUTSIDE_HEAP,
                            f"Pointer {hex(target_address)} resides in thread stack ({pname or cat}), not heap memory",
                        )
                    if pname and not pname.startswith("[") and "heap" not in pname.lower() and "anon" not in pname.lower():
                        return FreeValidationResult(
                            False,
                            FreeValidationOutcome.FREE_TARGET_OUTSIDE_HEAP,
                            f"Pointer {hex(target_address)} resides in static/global binary segment ({pname}), not heap memory",
                        )
                    if "r" in perms and "w" in perms:
                        in_heap = True
                        break
            if not in_heap:
                return FreeValidationResult(
                    False,
                    FreeValidationOutcome.FREE_TARGET_OUTSIDE_HEAP,
                    f"Pointer {hex(target_address)} does not belong to any mapped writable heap/anonymous region",
                )

        # Check chunk header if available
        if raw_header and len(raw_header) >= 2 * self.size_sz:
            header_size = 2 * self.size_sz
            if self.arch_bits == 64:
                size_flags = int.from_bytes(raw_header[8:16], "little")
            else:
                size_flags = int.from_bytes(raw_header[4:8], "little")
            mask = ~(self.malloc_alignment - 1) & 0xFFFFFFFFFFFFFFFF
            chunk_size = size_flags & mask
            is_mmapped = bool(size_flags & 0x2)

            if chunk_size < self.min_chunk_size and not is_mmapped:
                return FreeValidationResult(
                    False,
                    FreeValidationOutcome.FREE_TARGET_INVALID_BOUNDARY,
                    f"Chunk size {chunk_size} at {hex(target_address - header_size)} below minimum {self.min_chunk_size}B",
                )
            if chunk_size % self.malloc_alignment != 0 and not is_mmapped:
                return FreeValidationResult(
                    False,
                    FreeValidationOutcome.FREE_TARGET_INVALID_BOUNDARY,
                    f"Chunk size {chunk_size} not aligned to {self.malloc_alignment}B",
                )

            # Check if chunk is already released via next chunk's PREV_INUSE
            if next_chunk_raw and len(next_chunk_raw) >= header_size and not is_mmapped:
                if self.arch_bits == 64:
                    next_size_flags = int.from_bytes(next_chunk_raw[8:16], "little")
                else:
                    next_size_flags = int.from_bytes(next_chunk_raw[4:8], "little")
                if (next_size_flags & 0x1) == 0:
                    return FreeValidationResult(
                        False,
                        FreeValidationOutcome.FREE_TARGET_ALREADY_RELEASED,
                        f"Chunk at {hex(target_address - header_size)} is already in free state (next chunk PREV_INUSE==0)",
                    )

        # Check for confirmed double-free evidence (repeated free calls or multiple freelist records)
        if freelist_records and len(freelist_records) >= 2:
            return FreeValidationResult(
                False,
                FreeValidationOutcome.FREE_TARGET_DOUBLE_FREE,
                f"Double free confirmed: pointer {hex(target_address)} appeared multiple times ({len(freelist_records)}) in release stream",
            )

        return FreeValidationResult(True, FreeValidationOutcome.VALID, None)


class JemallocInspector(AllocatorInspector):
    """Inspector for FreeBSD/Facebook jemalloc."""

    def allocator_type(self) -> AllocatorType:
        return AllocatorType.JEMALLOC

    def inspect_chunk(
        self,
        raw_bytes: bytes,
        address: int,
        next_chunk_raw: Optional[bytes] = None,
        is_user_ptr: bool = False,
    ) -> ChunkInfo:
        # jemalloc metadata (run headers, slab bitmaps, extent trees) is stored out-of-band!
        # Memory mapping alone must NEVER be reported as is_allocated=True!
        return ChunkInfo(
            address=address,
            user_data_address=address,
            requested_size=None,
            chunk_size=len(raw_bytes),
            is_allocated=None,  # Cannot establish allocation status without extent metadata
            prev_inuse=False,
            is_mmapped=False,
            allocation_state_proven=False,
            flags={"out_of_band_metadata": True},
            is_valid_start=None,
            allocator_type=self.allocator_type(),
            limitations=[
                "jemalloc out-of-band extent/slab descriptor metadata unavailable; cannot certify allocation state from memory mapping alone"
            ],
        )

    def is_valid_allocation_start(self, address: int, maps: List[Dict[str, Any]]) -> Optional[bool]:
        # Without jemalloc slab/extent descriptors, valid start cannot be certified
        return None

    def validate_free_target(
        self,
        target_address: int,
        raw_header: Optional[bytes] = None,
        next_chunk_raw: Optional[bytes] = None,
        maps: Optional[List[Dict[str, Any]]] = None,
        freelist_records: Optional[List[Any]] = None,
    ) -> FreeValidationResult:
        if target_address == 0:
            return FreeValidationResult(True, FreeValidationOutcome.FREE_TARGET_NULL, None)
        if target_address % 8 != 0:
            return FreeValidationResult(
                False,
                FreeValidationOutcome.FREE_TARGET_MISALIGNED,
                f"Pointer {hex(target_address)} violates jemalloc 8-byte quantum alignment",
            )
        return FreeValidationResult(
            True,
            FreeValidationOutcome.FREE_TARGET_UNKNOWN_ALLOCATOR,
            "jemalloc out-of-band metadata unavailable; free contract cannot be authoritatively certified",
        )


class TcmallocInspector(AllocatorInspector):
    """Inspector for Google tcmalloc (Thread-Caching Malloc)."""

    def allocator_type(self) -> AllocatorType:
        return AllocatorType.TCMALLOC

    def inspect_chunk(
        self,
        raw_bytes: bytes,
        address: int,
        next_chunk_raw: Optional[bytes] = None,
        is_user_ptr: bool = False,
    ) -> ChunkInfo:
        # tcmalloc uses central span pagemap tables stored out-of-band!
        # Do not report is_allocated=True merely because memory is mapped.
        return ChunkInfo(
            address=address,
            user_data_address=address,
            requested_size=None,
            chunk_size=len(raw_bytes),
            is_allocated=None,
            prev_inuse=False,
            is_mmapped=False,
            allocation_state_proven=False,
            flags={"central_cache_pagemap": True},
            is_valid_start=None,
            allocator_type=self.allocator_type(),
            limitations=[
                "tcmalloc central cache span lookup and pagemap translation unavailable; cannot certify allocation state from memory mapping alone"
            ],
        )

    def is_valid_allocation_start(self, address: int, maps: List[Dict[str, Any]]) -> Optional[bool]:
        return None

    def validate_free_target(
        self,
        target_address: int,
        raw_header: Optional[bytes] = None,
        next_chunk_raw: Optional[bytes] = None,
        maps: Optional[List[Dict[str, Any]]] = None,
        freelist_records: Optional[List[Any]] = None,
    ) -> FreeValidationResult:
        if target_address == 0:
            return FreeValidationResult(True, FreeValidationOutcome.FREE_TARGET_NULL, None)
        if target_address % 8 != 0:
            return FreeValidationResult(
                False,
                FreeValidationOutcome.FREE_TARGET_MISALIGNED,
                f"Pointer {hex(target_address)} violates tcmalloc alignment",
            )
        return FreeValidationResult(
            True,
            FreeValidationOutcome.FREE_TARGET_UNKNOWN_ALLOCATOR,
            "tcmalloc pagemap unavailable; free contract cannot be authoritatively certified",
        )


class CustomAllocatorInspector(AllocatorInspector):
    """Inspector for embedded fixed-pool or application-specific custom allocators."""

    def __init__(self, schema: Optional[Dict[str, Any]] = None):
        self.schema = schema or {}

    def allocator_type(self) -> AllocatorType:
        return AllocatorType.EMBEDDED_CUSTOM

    def inspect_chunk(
        self,
        raw_bytes: bytes,
        address: int,
        next_chunk_raw: Optional[bytes] = None,
        is_user_ptr: bool = False,
    ) -> ChunkInfo:
        if not self.schema:
            return ChunkInfo(
                address=address,
                user_data_address=address,
                requested_size=None,
                chunk_size=len(raw_bytes),
                is_allocated=None,
                prev_inuse=False,
                allocation_state_proven=False,
                flags={"custom_pool": True},
                is_valid_start=None,
                allocator_type=self.allocator_type(),
                limitations=["Custom allocator chunk layout requires explicit schema metadata"],
            )

        block_size = self.schema.get("block_size", len(raw_bytes))
        pool_start = self.schema.get("pool_start", 0)
        is_valid_boundary = ((address - pool_start) % block_size == 0) if pool_start else True

        return ChunkInfo(
            address=address,
            user_data_address=address,
            requested_size=block_size,
            chunk_size=block_size,
            is_allocated=self.schema.get("is_allocated"),
            prev_inuse=False,
            allocation_state_proven=bool("is_allocated" in self.schema),
            flags={"custom_pool": True, "schema_configured": True},
            is_valid_start=is_valid_boundary,
            allocator_type=self.allocator_type(),
            limitations=[] if self.schema else ["Unspecified custom allocator layout"],
        )

    def is_valid_allocation_start(self, address: int, maps: List[Dict[str, Any]]) -> Optional[bool]:
        if not self.schema:
            return None
        pool_start = self.schema.get("pool_start", 0)
        block_size = self.schema.get("block_size", 0)
        if pool_start and block_size:
            return (address - pool_start) % block_size == 0
        return None

    def validate_free_target(
        self,
        target_address: int,
        raw_header: Optional[bytes] = None,
        next_chunk_raw: Optional[bytes] = None,
        maps: Optional[List[Dict[str, Any]]] = None,
        freelist_records: Optional[List[Any]] = None,
    ) -> FreeValidationResult:
        if target_address == 0:
            return FreeValidationResult(True, FreeValidationOutcome.FREE_TARGET_NULL, None)
        if not self.schema:
            return FreeValidationResult(
                True,
                FreeValidationOutcome.FREE_TARGET_UNKNOWN_ALLOCATOR,
                "Custom allocator schema not provided; free contract compliance unverified",
            )
        pool_start = self.schema.get("pool_start", 0)
        block_size = self.schema.get("block_size", 0)
        if pool_start and block_size and (target_address - pool_start) % block_size != 0:
            return FreeValidationResult(
                False,
                FreeValidationOutcome.FREE_TARGET_INVALID_BOUNDARY,
                f"Address {hex(target_address)} does not align with custom pool block boundary (block_size={block_size})",
            )
        return FreeValidationResult(True, FreeValidationOutcome.VALID, None)


class UnknownAllocatorInspector(AllocatorInspector):
    """Inspector for unidentifiable or unsupported target allocators."""

    def allocator_type(self) -> AllocatorType:
        return AllocatorType.UNKNOWN

    def inspect_chunk(
        self,
        raw_bytes: bytes,
        address: int,
        next_chunk_raw: Optional[bytes] = None,
        is_user_ptr: bool = False,
    ) -> ChunkInfo:
        return ChunkInfo(
            address=address,
            user_data_address=address,
            requested_size=None,
            chunk_size=0,
            is_allocated=None,
            prev_inuse=False,
            flags={},
            is_valid_start=None,
            allocation_state_proven=False,
            allocator_type=self.allocator_type(),
            limitations=["Unknown allocator: standard chunk layout assumptions refused"],
        )

    def is_valid_allocation_start(self, address: int, maps: List[Dict[str, Any]]) -> Optional[bool]:
        # Without allocator metadata, cannot prove an address is a valid allocation start
        return None

    def validate_free_target(
        self,
        target_address: int,
        raw_header: Optional[bytes] = None,
        next_chunk_raw: Optional[bytes] = None,
        maps: Optional[List[Dict[str, Any]]] = None,
        freelist_records: Optional[List[Any]] = None,
    ) -> FreeValidationResult:
        if target_address == 0:
            return FreeValidationResult(True, FreeValidationOutcome.FREE_TARGET_NULL, None)
        return FreeValidationResult(
            True,
            FreeValidationOutcome.FREE_TARGET_UNKNOWN_ALLOCATOR,
            "Unknown allocator: cannot verify free() contract compliance without allocator metadata",
        )


def detect_allocator(
    maps: List[Dict[str, Any]],
    symbols: Optional[List[str]] = None,
    custom_schema: Optional[Dict[str, Any]] = None,
    target_abi: Optional[Any] = None,
) -> AllocatorDetectionResult:
    """Detects target runtime allocator from memory maps and symbol signatures with confidence distinction.

    ``target_abi`` (a ``target_abi.TargetABI`` detected from the target) enables the IMP-015 gate: the
    glibc ptmalloc chunk layout is only interpreted when the (arch, libc) combination is in the support
    table; otherwise the result is the UNKNOWN inspector with an explicit support_status/limitation.
    ``target_abi=None`` keeps the ABI-agnostic behaviour for offline callers that have no live target.
    """
    res = _detect_allocator_unchecked(maps, symbols, custom_schema)
    if target_abi is not None and isinstance(res.inspector, GlibcPtMallocInspector):
        from .target_abi import FEATURE_ALLOCATOR_CHUNKS, check_support
        decision = check_support(target_abi, FEATURE_ALLOCATOR_CHUNKS)
        if not decision.supported:
            return AllocatorDetectionResult(
                inspector=UnknownAllocatorInspector(),
                confidence="UNKNOWN",
                basis=decision.message,
                limitations=[decision.message, "glibc ptmalloc chunk layout not interpreted on this target"],
                support_status=decision.status,
            )
        res.support_status = decision.status
    return res


def _detect_allocator_unchecked(
    maps: List[Dict[str, Any]],
    symbols: Optional[List[str]] = None,
    custom_schema: Optional[Dict[str, Any]] = None,
) -> AllocatorDetectionResult:
    if custom_schema:
        return AllocatorDetectionResult(
            inspector=CustomAllocatorInspector(schema=custom_schema),
            confidence="CONFIRMED",
            basis="Explicit custom allocator schema supplied by expert",
        )

    sym_set = set(symbols or [])

    # Confirmed symbol signatures
    if any("je_malloc" in s for s in sym_set) or any("jemalloc" in s for s in sym_set):
        return AllocatorDetectionResult(
            inspector=JemallocInspector(),
            confidence="CONFIRMED",
            basis="jemalloc symbols identified in target symbol table",
        )
    if any("tc_malloc" in s for s in sym_set) or any("tcmalloc" in s for s in sym_set):
        return AllocatorDetectionResult(
            inspector=TcmallocInspector(),
            confidence="CONFIRMED",
            basis="tcmalloc symbols identified in target symbol table",
        )
    if any("__libc_malloc" in s or "__default_morecore" in s for s in sym_set):
        return AllocatorDetectionResult(
            inspector=GlibcPtMallocInspector(),
            confidence="CONFIRMED",
            basis="glibc ptmalloc symbols identified in target symbol table",
        )

    # Check shared libraries in memory maps
    has_libc = False
    for m in maps:
        p = m.get("pathname") or m.get("name", "")
        if "libjemalloc" in p:
            return AllocatorDetectionResult(
                inspector=JemallocInspector(),
                confidence="CONFIRMED",
                basis=f"libjemalloc mapped in process memory space ({p})",
            )
        if "libtcmalloc" in p:
            return AllocatorDetectionResult(
                inspector=TcmallocInspector(),
                confidence="CONFIRMED",
                basis=f"libtcmalloc mapped in process memory space ({p})",
            )
        if "libc.so" in p or "libc-" in p:
            has_libc = True

    if has_libc:
        return AllocatorDetectionResult(
            inspector=GlibcPtMallocInspector(),
            confidence="PROBABLE",
            basis="Standard glibc C library mapped in process address space",
        )

    # Unknown allocator: never silently fall back to glibc!
    return AllocatorDetectionResult(
        inspector=UnknownAllocatorInspector(),
        confidence="UNKNOWN",
        basis="No recognized standard allocator libraries or symbols detected in target process",
        limitations=["Target allocator could not be authoritatively identified; refusing standard heap layout assumptions"],
    )


def classify_pointer_integrity(
    address: int,
    maps: List[Dict[str, Any]],
    inspector: Optional[AllocatorInspector] = None,
    memory_reader: Optional[Callable[[int, int], Optional[bytes]]] = None,
    freelist_records: Optional[Iterable[Any]] = None,
) -> PointerClassificationResult:
    """Classifies pointer integrity using process memory maps and AllocatorInspector.

    Returns one of:
    - OUT_OF_RANGE: Outside all mapped VMAs or within NULL guard page (< 0x1000).
    - MAPPED_READABLE: Resides in a valid readable VMA (e.g. stack, static data/text, mmap), but not heap.
    - ALLOCATED_OBJECT: Verified active heap allocation chunk.
    - FREED_CHUNK: Resides in a chunk that has been freed or is currently present in freelist.
    - INTERIOR_POINTER: Resides within a valid heap chunk boundary but offset from the chunk base.
    - UNKNOWN: Indeterminate allocator state or unknown allocator.
    """
    if address == 0 or 0 < address < 0x1000:
        return PointerClassificationResult(
            address=address,
            classification=PointerClassification.OUT_OF_RANGE,
            is_valid_pointer=False,
            reason="Pointer is NULL or within NULL guard page (< 0x1000)",
        )

    # 1. Locate VMA in memory maps
    target_vma = None
    for m in maps:
        def _parse_addr(v: Any) -> int:
            if isinstance(v, int):
                return v
            if isinstance(v, str):
                try:
                    return int(v, 16) if v.startswith("0x") else int(v)
                except Exception:
                    return 0
            return 0

        ms = m.get("start_int")
        if ms is None:
            ms = _parse_addr(m.get("start", 0))
        me = m.get("end_int")
        if me is None:
            me = _parse_addr(m.get("end", 0))

        if ms <= address < me:
            target_vma = m
            break

    if not target_vma:
        return PointerClassificationResult(
            address=address,
            classification=PointerClassification.OUT_OF_RANGE,
            is_valid_pointer=False,
            reason=f"Address 0x{address:x} is outside any mapped VMA",
        )

    perms = target_vma.get("permissions", "")
    p_name = target_vma.get("pathname") or target_vma.get("name", "")
    is_readable = ("r" in perms) or target_vma.get("is_readable", False)

    if not is_readable:
        return PointerClassificationResult(
            address=address,
            classification=PointerClassification.OUT_OF_RANGE,
            is_valid_pointer=False,
            vma_permissions=perms,
            vma_pathname=p_name,
            reason=f"Address resides in non-readable VMA ({perms})",
        )

    # 2. Check if VMA is heap
    is_heap = (target_vma.get("category") == "heap" or p_name == "[heap]")

    if not is_heap:
        return PointerClassificationResult(
            address=address,
            classification=PointerClassification.MAPPED_READABLE,
            is_valid_pointer=True,
            vma_permissions=perms,
            vma_pathname=p_name,
            reason=f"Address resides in valid readable VMA ({p_name or 'anon'})",
        )

    # 3. VMA is heap: inspect using AllocatorInspector
    alloc_type = inspector.allocator_type() if inspector else AllocatorType.UNKNOWN
    if alloc_type == AllocatorType.UNKNOWN or not inspector:
        return PointerClassificationResult(
            address=address,
            classification=PointerClassification.UNKNOWN,
            is_valid_pointer=False,
            vma_permissions=perms,
            vma_pathname=p_name,
            allocator_type=alloc_type,
            reason="Allocator type is UNKNOWN; refusing to assume standard glibc chunk layout",
            limitations=["Cannot authoritatively verify heap chunks without known allocator layout"],
        )

    # Check freelist records if supplied
    if freelist_records:
        for fr in freelist_records:
            fr_addr = fr if isinstance(fr, int) else (getattr(fr, "address", None) or (fr.get("address") if isinstance(fr, dict) else None))
            if fr_addr == address:
                return PointerClassificationResult(
                    address=address,
                    classification=PointerClassification.FREED_CHUNK,
                    is_valid_pointer=False,
                    vma_permissions=perms,
                    vma_pathname=p_name,
                    allocator_type=alloc_type,
                    reason="Pointer address matches an entry in allocator freelist",
                )

    # If GlibcPtMallocInspector:
    if isinstance(inspector, GlibcPtMallocInspector):
        align_sz = inspector.malloc_alignment
        is_aligned = (address % align_sz == 0)
        chunk_hdr_addr = address - 2 * inspector.size_sz

        if memory_reader:
            hdr_bytes = memory_reader(chunk_hdr_addr, 32)
            if hdr_bytes and len(hdr_bytes) >= 16:
                chunk = inspector.inspect_chunk(hdr_bytes, chunk_hdr_addr, is_user_ptr=False)
                if chunk.chunk_size and chunk.chunk_size >= inspector.min_chunk_size:
                    # Check physical next chunk PREV_INUSE
                    next_hdr_addr = chunk_hdr_addr + chunk.chunk_size
                    next_hdr_bytes = memory_reader(next_hdr_addr, 16)
                    if next_hdr_bytes and len(next_hdr_bytes) >= 16:
                        next_chunk = inspector.inspect_chunk(next_hdr_bytes, next_hdr_addr, is_user_ptr=False)
                        if not next_chunk.prev_inuse:
                            return PointerClassificationResult(
                                address=address,
                                classification=PointerClassification.FREED_CHUNK,
                                is_valid_pointer=False,
                                vma_permissions=perms,
                                vma_pathname=p_name,
                                allocator_type=alloc_type,
                                chunk_address=chunk_hdr_addr,
                                user_ptr=address,
                                chunk_size=chunk.chunk_size,
                                reason="Physical next chunk PREV_INUSE bit is 0, proving this chunk is freed",
                            )
                        else:
                            if is_aligned:
                                return PointerClassificationResult(
                                    address=address,
                                    classification=PointerClassification.ALLOCATED_OBJECT,
                                    is_valid_pointer=True,
                                    vma_permissions=perms,
                                    vma_pathname=p_name,
                                    allocator_type=alloc_type,
                                    chunk_address=chunk_hdr_addr,
                                    user_ptr=address,
                                    chunk_size=chunk.chunk_size,
                                    reason="Active heap chunk with verified next chunk PREV_INUSE bit",
                                )
                            else:
                                return PointerClassificationResult(
                                    address=address,
                                    classification=PointerClassification.INTERIOR_POINTER,
                                    is_valid_pointer=True,
                                    vma_permissions=perms,
                                    vma_pathname=p_name,
                                    allocator_type=alloc_type,
                                    chunk_address=chunk_hdr_addr,
                                    user_ptr=chunk_hdr_addr + 2 * inspector.size_sz,
                                    chunk_size=chunk.chunk_size,
                                    reason=f"Interior pointer at offset +{address - (chunk_hdr_addr + 2 * inspector.size_sz)} inside active heap chunk",
                                )

        # Without memory reader or read failure:
        if is_aligned:
            return PointerClassificationResult(
                address=address,
                classification=PointerClassification.ALLOCATED_OBJECT,
                is_valid_pointer=True,
                vma_permissions=perms,
                vma_pathname=p_name,
                allocator_type=alloc_type,
                reason="Address is aligned to allocator chunk quantum",
            )
        else:
            return PointerClassificationResult(
                address=address,
                classification=PointerClassification.INTERIOR_POINTER,
                is_valid_pointer=True,
                vma_permissions=perms,
                vma_pathname=p_name,
                allocator_type=alloc_type,
                reason="Address resides in heap but is not aligned to chunk start (interior pointer)",
            )

    # For other allocators (Jemalloc, Tcmalloc, Custom)
    valid_start = inspector.is_valid_allocation_start(address, maps)
    if valid_start is True:
        return PointerClassificationResult(
            address=address,
            classification=PointerClassification.ALLOCATED_OBJECT,
            is_valid_pointer=True,
            vma_permissions=perms,
            vma_pathname=p_name,
            allocator_type=alloc_type,
            reason=f"Address verified as allocation start for {alloc_type.value}",
        )
    elif valid_start is False:
        return PointerClassificationResult(
            address=address,
            classification=PointerClassification.INTERIOR_POINTER,
            is_valid_pointer=True,
            vma_permissions=perms,
            vma_pathname=p_name,
            allocator_type=alloc_type,
            reason=f"Address is not an allocation start for {alloc_type.value} (interior pointer)",
        )
    else:
        return PointerClassificationResult(
            address=address,
            classification=PointerClassification.UNKNOWN,
            is_valid_pointer=False,
            vma_permissions=perms,
            vma_pathname=p_name,
            allocator_type=alloc_type,
            reason=f"Indeterminate allocation state for {alloc_type.value}",
            limitations=getattr(inspector, "limitations", []),
        )
