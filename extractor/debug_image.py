"""External debug image provider and ELF build identity verification.

Supports stripped production binaries by decoupling runtime memory observation
from DWARF symbol resolution, verifying build-id and architecture compatibility.
"""

from dataclasses import asdict, dataclass, field
import os
import struct
import time
from typing import Any, Dict, List, Optional


@dataclass
class BinaryIdentity:
    """ELF metadata and build identity for a binary or debug artifact."""
    path: str
    elf_class: str          # "ELF32" or "ELF64"
    architecture: str       # "x86_64", "aarch64", "arm", "x86", etc.
    endianness: str         # "little" or "big"
    build_id: Optional[str] = None
    debuglink: Optional[Dict[str, Any]] = None  # {"filename": str, "crc": Optional[int]}
    stripped: bool = False
    has_debug_info: bool = False
    elf_type: Optional[str] = None              # "ET_EXEC", "ET_DYN", etc.
    entry_point: Optional[int] = None
    pt_loads: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CompatibilityResult:
    """Outcome of verifying compatibility between runtime binary and debug image."""
    compatible: bool
    reason: str  # "COMPATIBLE", "BUILD_ID_MISMATCH", "ARCHITECTURE_MISMATCH", etc.
    runtime_identity: Optional[BinaryIdentity] = None
    debug_identity: Optional[BinaryIdentity] = None
    verification_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "compatible": self.compatible,
            "reason": self.reason,
            "runtime_identity": self.runtime_identity.to_dict() if self.runtime_identity else None,
            "debug_identity": self.debug_identity.to_dict() if self.debug_identity else None,
            "verification_ms": self.verification_ms,
        }


def inspect_elf(path: str) -> BinaryIdentity:
    """Inspect an ELF binary file and extract its architecture, build ID, and debug sections.

    Pure-Python parser with zero external dependencies.
    """
    if not os.path.exists(path):
        raise FileNotFoundError("Binary file not found: {}".format(path))

    with open(path, "rb") as f:
        ident = f.read(16)
        if len(ident) < 16 or ident[:4] != b"\x7fELF":
            raise ValueError("Invalid ELF magic: '{}' is not an ELF binary".format(path))

        ei_class = ident[4]
        if ei_class not in (1, 2):
            raise ValueError("Unsupported ELF class: {}".format(ei_class))
        is_64 = (ei_class == 2)

        ei_data = ident[5]
        if ei_data not in (1, 2):
            raise ValueError("Unsupported ELF endianness: {}".format(ei_data))
        endian = "<" if ei_data == 1 else ">"

        f.seek(16)
        if is_64:
            hdr_bytes = f.read(48)
            if len(hdr_bytes) < 48:
                raise ValueError("Truncated ELF64 header: {}".format(path))
            e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = struct.unpack(
                endian + "HHIQQQIHHHHHH", hdr_bytes
            )
        else:
            hdr_bytes = f.read(36)
            if len(hdr_bytes) < 36:
                raise ValueError("Truncated ELF32 header: {}".format(path))
            e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = struct.unpack(
                endian + "HHIIIIIHHHHHH", hdr_bytes
            )

        arch_map = {
            3: "x86",
            62: "x86_64",
            40: "arm",
            183: "aarch64",
            243: "riscv",
        }
        arch_name = arch_map.get(e_machine, "machine_0x{:04x}".format(e_machine))

        # Read section header table if present
        sections = []
        if e_shoff > 0 and e_shnum > 0 and e_shentsize > 0:
            f.seek(e_shoff)
            sh_data = f.read(e_shentsize * e_shnum)
            for i in range(e_shnum):
                chunk = sh_data[i * e_shentsize : (i + 1) * e_shentsize]
                if len(chunk) < e_shentsize:
                    break
                if is_64:
                    sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize = struct.unpack(
                        endian + "IIQQQQIIQQ", chunk
                    )
                else:
                    sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize = struct.unpack(
                        endian + "IIIIIIIIII", chunk
                    )
                sections.append({
                    "name_idx": sh_name,
                    "type": sh_type,
                    "offset": sh_offset,
                    "size": sh_size,
                })

        # Read section names from shstrtab
        strtab = b""
        if 0 <= e_shstrndx < len(sections):
            shstr = sections[e_shstrndx]
            f.seek(shstr["offset"])
            strtab = f.read(shstr["size"])

        def get_str(idx: int) -> str:
            if idx >= len(strtab):
                return ""
            end = strtab.find(b"\x00", idx)
            if end == -1:
                end = len(strtab)
            return strtab[idx:end].decode("latin1", errors="replace")

        sec_names = set()
        build_id = None
        debuglink = None

        for s in sections:
            name = get_str(s["name_idx"])
            s["name"] = name
            sec_names.add(name)

            # Check for GNU Build ID note
            if name == ".note.gnu.build-id" or (s["type"] == 7 and "build-id" in name):
                f.seek(s["offset"])
                note_bytes = f.read(s["size"])
                # Note format: namesz (4), descsz (4), type (4), name (padded), desc (padded)
                n_offset = 0
                while n_offset + 12 <= len(note_bytes):
                    namesz, descsz, ntype = struct.unpack(endian + "III", note_bytes[n_offset : n_offset + 12])
                    n_offset += 12
                    padded_namesz = (namesz + 3) & ~3
                    padded_descsz = (descsz + 3) & ~3
                    if n_offset + padded_namesz + descsz > len(note_bytes):
                        break
                    n_name = note_bytes[n_offset : n_offset + namesz].rstrip(b"\x00")
                    desc_bytes = note_bytes[n_offset + padded_namesz : n_offset + padded_namesz + descsz]
                    if ntype == 3 and (n_name == b"GNU" or not n_name):  # NT_GNU_BUILD_ID
                        build_id = desc_bytes.hex()
                        break
                    n_offset += padded_namesz + padded_descsz

            # Check for .gnu_debuglink section
            elif name == ".gnu_debuglink":
                f.seek(s["offset"])
                dl_bytes = f.read(s["size"])
                null_pos = dl_bytes.find(b"\x00")
                if null_pos != -1:
                    dl_filename = dl_bytes[:null_pos].decode("latin1", errors="replace")
                    padded_pos = (null_pos + 1 + 3) & ~3
                    crc = None
                    if len(dl_bytes) >= padded_pos + 4:
                        crc = struct.unpack(endian + "I", dl_bytes[padded_pos : padded_pos + 4])[0]
                    debuglink = {"filename": dl_filename, "crc": crc}

        elf_type_map = {
            1: "ET_REL",
            2: "ET_EXEC",
            3: "ET_DYN",
            4: "ET_CORE",
        }
        elf_type_name = elf_type_map.get(e_type, "ET_0x{:04x}".format(e_type))

        # Program headers: read PT_LOAD segments and PT_NOTE (if needed)
        pt_loads = []
        if e_phoff > 0 and e_phnum > 0 and e_phentsize > 0:
            f.seek(e_phoff)
            ph_data = f.read(e_phentsize * e_phnum)
            for i in range(e_phnum):
                chunk = ph_data[i * e_phentsize : (i + 1) * e_phentsize]
                if len(chunk) < e_phentsize:
                    break
                p_type = struct.unpack(endian + "I", chunk[:4])[0]
                if p_type == 1:  # PT_LOAD
                    if is_64:
                        p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack(
                            endian + "IQQQQQQ", chunk[4:56]
                        )
                    else:
                        p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = struct.unpack(
                            endian + "IIIIIII", chunk[4:32]
                        )
                    pt_loads.append({
                        "p_type": 1,
                        "p_offset": p_offset,
                        "p_vaddr": p_vaddr,
                        "p_paddr": p_paddr,
                        "p_filesz": p_filesz,
                        "p_memsz": p_memsz,
                        "p_flags": p_flags,
                        "p_align": p_align,
                    })
                elif p_type == 4 and not build_id:  # PT_NOTE
                    if is_64:
                        p_flags, p_offset, p_vaddr, p_paddr, p_filesz = struct.unpack(endian + "IQQQQ", chunk[4:40])
                    else:
                        p_offset, p_vaddr, p_paddr, p_filesz = struct.unpack(endian + "IIII", chunk[4:20])
                    f.seek(p_offset)
                    note_bytes = f.read(p_filesz)
                    n_offset = 0
                    while n_offset + 12 <= len(note_bytes):
                        namesz, descsz, ntype = struct.unpack(endian + "III", note_bytes[n_offset : n_offset + 12])
                        n_offset += 12
                        padded_namesz = (namesz + 3) & ~3
                        padded_descsz = (descsz + 3) & ~3
                        if n_offset + padded_namesz + descsz > len(note_bytes):
                            break
                        n_name = note_bytes[n_offset : n_offset + namesz].rstrip(b"\x00")
                        desc_bytes = note_bytes[n_offset + padded_namesz : n_offset + padded_namesz + descsz]
                        if ntype == 3 and (n_name == b"GNU" or not n_name):
                            build_id = desc_bytes.hex()
                            break
                        n_offset += padded_namesz + padded_descsz

        has_debug_info = any(s.startswith(".debug_") or s == ".gdb_index" for s in sec_names)
        is_stripped = (".symtab" not in sec_names) and not has_debug_info

        return BinaryIdentity(
            path=os.path.abspath(path),
            elf_class="ELF64" if is_64 else "ELF32",
            architecture=arch_name,
            endianness="little" if ei_data == 1 else "big",
            build_id=build_id,
            debuglink=debuglink,
            stripped=is_stripped,
            has_debug_info=has_debug_info,
            elf_type=elf_type_name,
            entry_point=e_entry,
            pt_loads=pt_loads,
        )


class DebugImageProvider:
    """Manages discovery, verification, and binding of external debug images.

    Ensures that stripped production binaries only bind to matching debug artifacts
    sharing the exact same GNU Build ID and ELF architecture characteristics.
    """

    def __init__(self, debug_image_path: Optional[str] = None):
        self.debug_image_path: Optional[str] = None
        self.debug_identity: Optional[BinaryIdentity] = None
        self.runtime_identity: Optional[BinaryIdentity] = None
        self.compatibility: Optional[CompatibilityResult] = None
        self.module_debug_images: Dict[str, str] = {}
        self.load_ms: float = 0.0
        self.identity_check_ms: float = 0.0
        self.verification_ms: float = 0.0

        if debug_image_path:
            self.load(debug_image_path)

    def load(self, path: str) -> BinaryIdentity:
        """Load and parse candidate external debug image."""
        t0 = time.monotonic()
        identity = inspect_elf(path)
        self.debug_image_path = os.path.abspath(path)
        self.debug_identity = identity
        self.load_ms = round((time.monotonic() - t0) * 1000, 3)
        return identity

    @property
    def path(self) -> Optional[str]:
        return self.debug_image_path

    def register_module_debug_image(self, module_name_or_path: str, debug_image_path: str) -> None:
        """Register debug image mapping for a shared library module."""
        self.module_debug_images[module_name_or_path] = os.path.abspath(debug_image_path)

    def get_module_debug_image(self, module_name_or_path: str) -> Optional[str]:
        """Query external debug image path registered for a shared library."""
        return self.module_debug_images.get(module_name_or_path)

    def verify(self, runtime_binary_path: str) -> CompatibilityResult:
        """Verify strict compatibility between runtime binary and debug image."""
        t0 = time.monotonic()

        if not self.debug_identity:
            res = CompatibilityResult(
                compatible=False,
                reason="DEBUG_IMAGE_NOT_LOADED",
                verification_ms=round((time.monotonic() - t0) * 1000, 3)
            )
            self.compatibility = res
            return res

        t_id_start = time.monotonic()
        try:
            runtime_id = inspect_elf(runtime_binary_path)
            self.runtime_identity = runtime_id
        except FileNotFoundError:
            res = CompatibilityResult(
                compatible=False,
                reason="RUNTIME_BINARY_NOT_FOUND",
                debug_identity=self.debug_identity,
                verification_ms=round((time.monotonic() - t0) * 1000, 3)
            )
            self.compatibility = res
            return res
        except Exception as exc:
            res = CompatibilityResult(
                compatible=False,
                reason="INVALID_ELF_IMAGE: {}".format(exc),
                debug_identity=self.debug_identity,
                verification_ms=round((time.monotonic() - t0) * 1000, 3)
            )
            self.compatibility = res
            return res
        finally:
            self.identity_check_ms = round((time.monotonic() - t_id_start) * 1000, 3)

        debug_id = self.debug_identity

        # 1. Architecture compatibility check
        if (runtime_id.elf_class != debug_id.elf_class or
                runtime_id.architecture != debug_id.architecture or
                runtime_id.endianness != debug_id.endianness):
            res = CompatibilityResult(
                compatible=False,
                reason="ARCHITECTURE_MISMATCH",
                runtime_identity=runtime_id,
                debug_identity=debug_id,
                verification_ms=round((time.monotonic() - t0) * 1000, 3)
            )
            self.compatibility = res
            self.verification_ms = res.verification_ms
            return res

        # 2. Build ID comparison (Strongest authority)
        if runtime_id.build_id and debug_id.build_id:
            if runtime_id.build_id != debug_id.build_id:
                res = CompatibilityResult(
                    compatible=False,
                    reason="BUILD_ID_MISMATCH",
                    runtime_identity=runtime_id,
                    debug_identity=debug_id,
                    verification_ms=round((time.monotonic() - t0) * 1000, 3)
                )
                self.compatibility = res
                self.verification_ms = res.verification_ms
                return res
            # Matching Build ID
            reason = "COMPATIBLE"
        elif runtime_id.debuglink and self.debug_image_path:
            # Fallback to .gnu_debuglink if build ID missing in either
            expected_name = runtime_id.debuglink.get("filename")
            actual_name = os.path.basename(self.debug_image_path)
            if expected_name == actual_name:
                reason = "COMPATIBLE_DEBUGLINK"
            else:
                res = CompatibilityResult(
                    compatible=False,
                    reason="BUILD_ID_NOT_AVAILABLE",
                    runtime_identity=runtime_id,
                    debug_identity=debug_id,
                    verification_ms=round((time.monotonic() - t0) * 1000, 3)
                )
                self.compatibility = res
                self.verification_ms = res.verification_ms
                return res
        else:
            # Build ID not available and no debuglink match
            res = CompatibilityResult(
                compatible=False,
                reason="BUILD_ID_NOT_AVAILABLE",
                runtime_identity=runtime_id,
                debug_identity=debug_id,
                verification_ms=round((time.monotonic() - t0) * 1000, 3)
            )
            self.compatibility = res
            self.verification_ms = res.verification_ms
            return res

        # 3. Ensure debug image actually contains debug info or symbols
        if not debug_id.has_debug_info and debug_id.stripped:
            res = CompatibilityResult(
                compatible=False,
                reason="DEBUG_INFO_MISSING",
                runtime_identity=runtime_id,
                debug_identity=debug_id,
                verification_ms=round((time.monotonic() - t0) * 1000, 3)
            )
            self.compatibility = res
            self.verification_ms = res.verification_ms
            return res

        res = CompatibilityResult(
            compatible=True,
            reason=reason,
            runtime_identity=runtime_id,
            debug_identity=debug_id,
            verification_ms=round((time.monotonic() - t0) * 1000, 3)
        )
        self.compatibility = res
        self.verification_ms = res.verification_ms
        return res

    def get_path(self) -> Optional[str]:
        return self.debug_image_path

    def get_build_id(self) -> Optional[str]:
        return self.debug_identity.build_id if self.debug_identity else None

    def get_provenance(self) -> Dict[str, Any]:
        """Construct provenance metadata dictionary for snapshots."""
        runtime_dict = None
        if self.runtime_identity:
            runtime_dict = {
                "path": self.runtime_identity.path,
                "build_id": self.runtime_identity.build_id,
                "architecture": self.runtime_identity.architecture,
                "elf_class": self.runtime_identity.elf_class,
                "endianness": self.runtime_identity.endianness,
                "stripped": self.runtime_identity.stripped
            }

        debug_dict = None
        if self.debug_identity:
            debug_dict = {
                "path": self.debug_identity.path,
                "build_id": self.debug_identity.build_id,
                "architecture": self.debug_identity.architecture,
                "elf_class": self.debug_identity.elf_class,
                "endianness": self.debug_identity.endianness,
                "source": "external" if (not self.runtime_identity or self.debug_identity.path != self.runtime_identity.path) else "embedded",
                "verified": bool(self.compatibility and self.compatibility.compatible),
                "compatible": bool(self.compatibility and self.compatibility.compatible),
                "reason": self.compatibility.reason if self.compatibility else None
            }

        return {
            "runtime_binary": runtime_dict,
            "debug_image": debug_dict,
            "performance": {
                "debug_image_load_ms": self.load_ms,
                "binary_identity_check_ms": self.identity_check_ms,
                "debug_image_verification_ms": self.verification_ms
            }
        }
