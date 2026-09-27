"""Debug artifact discovery and GNU debuglink / Build-ID verification (Phase 5.2).

Discovers and verifies external debug images for runtime modules following strict precedence:
1. Explicitly registered debug image (--debug-image)
2. Build ID lookup (/usr/lib/debug/.build-id/xx/yyyyyyyy.debug)
3. .gnu_debuglink lookup (adjacent .debug, /usr/lib/debug with CRC verification)
4. Runtime binary itself (if unstripped with debug sections)
"""

import os
import time
import zlib
from typing import Any, Dict, List, Optional

from .debug_image import BinaryIdentity, CompatibilityResult, inspect_elf
from .modules import RuntimeModule


def compute_gnu_debuglink_crc(file_path: str) -> int:
    """Compute the CRC-32 checksum used by .gnu_debuglink."""
    crc = 0
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            crc = zlib.crc32(chunk, crc)
    return crc & 0xFFFFFFFF


class DebugArtifactProvider:
    """Manages debug artifact resolution and verification for runtime modules."""

    def __init__(self, search_paths: Optional[List[str]] = None):
        self.search_paths: List[str] = [
            os.path.abspath(p) for p in (search_paths or ["/usr/lib/debug", ".", "./debug"])
        ]
        self._explicit_images: Dict[str, str] = {}
        self._ident_cache: Dict[str, BinaryIdentity] = {}

    def register(self, module_key: str, debug_image_path: str) -> None:
        """Explicitly associate a debug image with a module (by id, path, or filename)."""
        abs_dbg = os.path.abspath(debug_image_path)
        self._explicit_images[module_key] = abs_dbg
        self._explicit_images[os.path.basename(module_key)] = abs_dbg

    def add_search_path(self, path: str) -> None:
        """Add a directory to the debug artifact search path."""
        abs_p = os.path.abspath(path)
        if abs_p not in self.search_paths:
            self.search_paths.append(abs_p)

    def get_ident(self, path: str) -> BinaryIdentity:
        """Retrieve cached ELF identity for a binary or debug artifact."""
        abs_p = os.path.abspath(path)
        if abs_p not in self._ident_cache:
            self._ident_cache[abs_p] = inspect_elf(abs_p)
        return self._ident_cache[abs_p]

    def find_debug_artifact(self, module: RuntimeModule) -> Optional[str]:
        """Discover candidate debug artifact following defined lookup precedence."""
        # 1. Explicit registration
        for key in (module.module_id, module.path, os.path.basename(module.path)):
            if key and key in self._explicit_images:
                cand = self._explicit_images[key]
                if os.path.exists(cand):
                    return cand

        # 2. Build ID lookup
        if module.build_id and len(module.build_id) >= 4:
            prefix = module.build_id[:2]
            suffix = module.build_id[2:]
            rel_bid = os.path.join(".build-id", prefix, f"{suffix}.debug")
            for sp in self.search_paths:
                cand = os.path.join(sp, rel_bid)
                if os.path.exists(cand):
                    return cand

        # 3. .gnu_debuglink lookup
        if module.debuglink and module.debuglink.get("filename"):
            dl_filename = module.debuglink["filename"]
            bin_dir = os.path.dirname(module.path) if module.path else "."

            candidate_paths = [
                os.path.join(bin_dir, dl_filename),
                os.path.join(bin_dir, ".debug", dl_filename),
            ]
            for sp in self.search_paths:
                candidate_paths.append(os.path.join(sp, bin_dir.lstrip("/"), dl_filename))
                candidate_paths.append(os.path.join(sp, dl_filename))

            expected_crc = module.debuglink.get("crc")
            for cand in candidate_paths:
                if os.path.exists(cand):
                    if expected_crc is not None:
                        actual_crc = compute_gnu_debuglink_crc(cand)
                        if actual_crc == expected_crc:
                            return cand
                    else:
                        return cand

        # 4. Runtime binary itself (if it contains DWARF/debug info)
        if module.path and os.path.exists(module.path):
            try:
                info = self.get_ident(module.path)
                if info.has_debug_info:
                    return module.path
            except Exception:
                pass

        return None

    def verify(
        self, module: RuntimeModule, debug_artifact_path: str
    ) -> CompatibilityResult:
        """Verify strict compatibility between runtime module and debug image."""
        t0 = time.monotonic()
        if not os.path.exists(debug_artifact_path):
            return CompatibilityResult(
                compatible=False,
                reason="DEBUG_IMAGE_NOT_FOUND",
                verification_ms=round((time.monotonic() - t0) * 1000, 3)
            )

        try:
            dbg_ident = self.get_ident(debug_artifact_path)
        except Exception as exc:
            return CompatibilityResult(
                compatible=False,
                reason=f"INVALID_DEBUG_IMAGE: {exc}",
                verification_ms=round((time.monotonic() - t0) * 1000, 3)
            )

        # 1. Architecture compatibility
        if module.architecture and dbg_ident.architecture:
            if module.architecture != dbg_ident.architecture:
                return CompatibilityResult(
                    compatible=False,
                    reason=f"ARCHITECTURE_MISMATCH: runtime={module.architecture}, debug={dbg_ident.architecture}",
                    debug_identity=dbg_ident,
                    verification_ms=round((time.monotonic() - t0) * 1000, 3)
                )

        # 2. ELF Class & Endianness compatibility
        if module.elf_class and dbg_ident.elf_class:
            if module.elf_class != dbg_ident.elf_class:
                return CompatibilityResult(
                    compatible=False,
                    reason=f"ELF_CLASS_MISMATCH: runtime={module.elf_class}, debug={dbg_ident.elf_class}",
                    debug_identity=dbg_ident,
                    verification_ms=round((time.monotonic() - t0) * 1000, 3)
                )

        if module.endianness and dbg_ident.endianness:
            if module.endianness != dbg_ident.endianness:
                return CompatibilityResult(
                    compatible=False,
                    reason=f"ENDIANNESS_MISMATCH: runtime={module.endianness}, debug={dbg_ident.endianness}",
                    debug_identity=dbg_ident,
                    verification_ms=round((time.monotonic() - t0) * 1000, 3)
                )

        # 3. Build ID compatibility (if present in both)
        if module.build_id and dbg_ident.build_id:
            if module.build_id.lower() != dbg_ident.build_id.lower():
                return CompatibilityResult(
                    compatible=False,
                    reason="DEBUG_IMAGE_MISMATCH",
                    debug_identity=dbg_ident,
                    verification_ms=round((time.monotonic() - t0) * 1000, 3)
                )

        # 4. Must contain debug info
        if not dbg_ident.has_debug_info:
            return CompatibilityResult(
                compatible=False,
                reason="DEBUG_IMAGE_STRIPPED",
                debug_identity=dbg_ident,
                verification_ms=round((time.monotonic() - t0) * 1000, 3)
            )

        return CompatibilityResult(
            compatible=True,
            reason="COMPATIBLE",
            debug_identity=dbg_ident,
            verification_ms=round((time.monotonic() - t0) * 1000, 3)
        )
