"""Static analysis provider interface and adapters for evidence-linked code correlation.

Supports function inspection, symbol/reference lookup, and call relationship retrieval,
connecting runtime observations to static code only when module identity, Build ID,
and load bias provide a defensible basis.
"""

from abc import ABC, abstractmethod
import os
import re
import subprocess
import threading
from typing import Any, Dict, List, Optional, Set, Tuple, Union


def _low_priority_preexec() -> None:
    """Lower CPU scheduling priority for background binutils subprocesses so interactive
    terminals and target processes never experience keystroke lag."""
    try:
        os.nice(10)
    except Exception:
        pass

from .dwarf_indexer import DwarfIndex, DwarfIndexer
from .modules import ModuleAddressResolver, RuntimeModule


# Link kinds
LINK_KIND_TYPE_DEFINITION = "TYPE_DEFINITION"
LINK_KIND_GLOBAL_VARIABLE = "GLOBAL_VARIABLE"
LINK_KIND_FUNCTION_ADDRESS = "FUNCTION_ADDRESS"
LINK_KIND_CALL_RELATIONSHIP = "CALL_RELATIONSHIP"
LINK_KIND_FIELD_WRITE_CANDIDATE = "FIELD_WRITE_CANDIDATE"
LINK_KIND_SOURCE_LOCATION = "SOURCE_LOCATION"
LINK_KIND_UNRESOLVED = "UNRESOLVED"

# Identity status constants
IDENTITY_VERIFIED_MATCH = "VERIFIED_MATCH"
IDENTITY_MISMATCH = "MISMATCH"
IDENTITY_TARGET_ID_UNAVAILABLE = "TARGET_ID_UNAVAILABLE"
IDENTITY_DEBUG_ID_UNAVAILABLE = "DEBUG_ID_UNAVAILABLE"
IDENTITY_INCOMPLETE = "INCOMPLETE"

from dataclasses import asdict, dataclass

# Evidence level constants
EVIDENCE_LEVEL_OBSERVED = "observed"
EVIDENCE_LEVEL_STATIC = "static"
EVIDENCE_LEVEL_INDIRECT = "indirect"
EVIDENCE_LEVEL_UNKNOWN = "unknown"

# Explicit function candidate tiers
FUNCTION_TIER_STATIC_CANDIDATE = "STATIC_CANDIDATE"
FUNCTION_TIER_EVIDENCE_SUPPORTED = "EVIDENCE_SUPPORTED_CANDIDATE"
FUNCTION_TIER_VALIDATED_CAUSAL = "VALIDATED_CAUSAL_FUNCTION"
FUNCTION_TIER_UNKNOWN = "UNKNOWN"

LAYOUT_MUTATION_CAVEAT = (
    "DWARF member declaration specifies struct memory layout only; "
    "it does NOT prove where this field was mutated at runtime."
)


@dataclass
class FunctionCandidate:
    """Represents a candidate function correlated to an object or field."""
    function_name: str
    source_location: Optional[str]
    related_target: str
    reason: str
    evidence_level: str  # "observed", "static", "indirect", "unknown"
    basis_source: str
    limitations: str
    thread_id: Optional[Union[int, str]] = None
    frame_level: Optional[int] = None
    causal_classification: str = FUNCTION_TIER_STATIC_CANDIDATE
    confirmed_root_cause: bool = False

    def __post_init__(self):
        if self.evidence_level == EVIDENCE_LEVEL_OBSERVED:
            self.causal_classification = FUNCTION_TIER_EVIDENCE_SUPPORTED
        elif self.evidence_level in (EVIDENCE_LEVEL_STATIC, EVIDENCE_LEVEL_INDIRECT):
            self.causal_classification = FUNCTION_TIER_STATIC_CANDIDATE
        elif self.evidence_level == EVIDENCE_LEVEL_UNKNOWN:
            self.causal_classification = FUNCTION_TIER_UNKNOWN

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def validate_module_identity(
    target_build_id: Optional[str],
    debug_build_id: Optional[str],
) -> Tuple[str, str]:
    """Validate target module vs debug image identity.

    Returns (status, reason) where status is one of:
    - VERIFIED_MATCH: Both have Build IDs and they match exactly.
    - MISMATCH: Both have Build IDs and they conflict.
    - TARGET_ID_UNAVAILABLE: Target lacks Build ID (debug Build ID alone does not prove match).
    - DEBUG_ID_UNAVAILABLE: Debug artifact lacks Build ID.
    - INCOMPLETE: Insufficient identity evidence.
    """
    if target_build_id and debug_build_id:
        if target_build_id == debug_build_id:
            return IDENTITY_VERIFIED_MATCH, "Target module and debug image Build IDs match."
        else:
            return IDENTITY_MISMATCH, f"Target Build ID '{target_build_id}' conflicts with debug image Build ID '{debug_build_id}'."
    elif not target_build_id and debug_build_id:
        return IDENTITY_TARGET_ID_UNAVAILABLE, "Target module Build ID cannot be established; debug image Build ID alone does not prove a match."
    elif target_build_id and not debug_build_id:
        return IDENTITY_DEBUG_ID_UNAVAILABLE, "Debug image does not contain a GNU Build ID."
    else:
        return IDENTITY_INCOMPLETE, "Insufficient identity evidence: neither target module nor debug image provided a Build ID."


class StaticAnalysisProvider(ABC):
    """Abstract interface for static analysis backends (DWARF, REA, Ghidra, etc.)."""

    @abstractmethod
    def is_available(self) -> bool:
        """Returns True if the provider backend is installed and operational."""
        pass

    @abstractmethod
    def get_provider_name(self) -> str:
        """Name of the provider backend."""
        pass

    @abstractmethod
    def inspect_function(
        self,
        name_or_addr: Union[str, int],
        module: Optional[RuntimeModule] = None,
    ) -> Optional[Dict[str, Any]]:
        """Retrieve static metadata for a function by name or static ELF address."""
        pass

    @abstractmethod
    def lookup_symbol(
        self,
        symbol_name: str,
        module: Optional[RuntimeModule] = None,
    ) -> Optional[Dict[str, Any]]:
        """Look up static symbol definition and declaration location."""
        pass

    @abstractmethod
    def find_references(
        self,
        name_or_addr: Union[str, int],
        module: Optional[RuntimeModule] = None,
    ) -> List[Dict[str, Any]]:
        """Find static references to a symbol or function."""
        pass

    @abstractmethod
    def get_call_relationships(
        self,
        function_name: str,
        module: Optional[RuntimeModule] = None,
    ) -> Dict[str, Any]:
        """Retrieve static callers and callees for a function."""
        pass

    @abstractmethod
    def resolve_runtime_to_code(
        self,
        runtime_addr: int,
        module: Optional[RuntimeModule] = None,
        type_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Correlate a runtime memory address to static source code with defensible basis."""
        pass


class NullStaticAnalysisProvider(StaticAnalysisProvider):
    """Fallback provider when no static analysis backend or debug information is available."""

    def is_available(self) -> bool:
        return True

    def get_provider_name(self) -> str:
        return "null"

    def inspect_function(self, name_or_addr: Union[str, int], module: Optional[RuntimeModule] = None) -> Optional[Dict[str, Any]]:
        return None

    def lookup_symbol(self, symbol_name: str, module: Optional[RuntimeModule] = None) -> Optional[Dict[str, Any]]:
        return None

    def find_references(self, name_or_addr: Union[str, int], module: Optional[RuntimeModule] = None) -> List[Dict[str, Any]]:
        return []

    def get_call_relationships(self, function_name: str, module: Optional[RuntimeModule] = None) -> Dict[str, Any]:
        return {"callers": [], "callees": [], "status": "UNSUPPORTED"}

    def resolve_runtime_to_code(
        self,
        runtime_addr: int,
        module: Optional[RuntimeModule] = None,
        type_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        return {
            "status": "UNRESOLVED_NO_PROVIDER",
            "link_kind": LINK_KIND_UNRESOLVED,
            "is_verified": False,
            "runtime_address": "0x{:x}".format(runtime_addr),
            "link_basis": None,
            "reason": "No static analysis backend configured.",
        }


class MockStaticAnalysisProvider(StaticAnalysisProvider):
    """Test provider for deterministic testing of static-analysis integration."""

    def __init__(self, name: str = "mock"):
        self.name = name
        self.functions: Dict[str, Dict[str, Any]] = {}
        self.symbols: Dict[str, Dict[str, Any]] = {}
        self.references: Dict[str, List[Dict[str, Any]]] = {}
        self.calls: Dict[str, Dict[str, Any]] = {}
        self.custom_mappings: Dict[int, Dict[str, Any]] = {}

    def is_available(self) -> bool:
        return True

    def get_provider_name(self) -> str:
        return self.name

    def inspect_function(self, name_or_addr: Union[str, int], module: Optional[RuntimeModule] = None) -> Optional[Dict[str, Any]]:
        key = str(name_or_addr)
        return self.functions.get(key)

    def lookup_symbol(self, symbol_name: str, module: Optional[RuntimeModule] = None) -> Optional[Dict[str, Any]]:
        return self.symbols.get(symbol_name)

    def find_references(self, name_or_addr: Union[str, int], module: Optional[RuntimeModule] = None) -> List[Dict[str, Any]]:
        key = str(name_or_addr)
        return self.references.get(key, [])

    def get_call_relationships(self, function_name: str, module: Optional[RuntimeModule] = None) -> Dict[str, Any]:
        return self.calls.get(function_name, {"callers": [], "callees": [], "status": "EMPTY"})

    def resolve_runtime_to_code(
        self,
        runtime_addr: int,
        module: Optional[RuntimeModule] = None,
        type_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        if runtime_addr in self.custom_mappings:
            return self.custom_mappings[runtime_addr]

        if module and module.build_id_status in (IDENTITY_MISMATCH, "MISMATCH"):
            return {
                "status": "UNRESOLVED_BUILD_ID_MISMATCH",
                "link_kind": LINK_KIND_UNRESOLVED,
                "is_verified": False,
                "runtime_address": "0x{:x}".format(runtime_addr),
                "link_basis": None,
                "reason": f"Module '{module.module_id}' build ID mismatches debug image.",
            }

        if module and module.build_id_status in (
            IDENTITY_TARGET_ID_UNAVAILABLE,
            IDENTITY_DEBUG_ID_UNAVAILABLE,
            IDENTITY_INCOMPLETE,
            "NOT_AVAILABLE",
            "UNREADABLE",
        ):
            return {
                "status": "UNRESOLVED_IDENTITY_UNVERIFIED",
                "link_kind": LINK_KIND_UNRESOLVED,
                "is_verified": False,
                "runtime_address": "0x{:x}".format(runtime_addr),
                "link_basis": None,
                "reason": f"Module '{module.module_id}' identity cannot be reliably verified ({module.build_id_status}).",
            }

        if module and (module.load_bias_status != "RESOLVED" or module.load_bias is None):
            return {
                "status": "UNRESOLVED_LOAD_BIAS",
                "link_kind": LINK_KIND_UNRESOLVED,
                "is_verified": False,
                "runtime_address": "0x{:x}".format(runtime_addr),
                "link_basis": None,
                "reason": "Cannot translate runtime address with UNRESOLVED load bias.",
            }

        # Check static address
        static_addr = runtime_addr
        if module and module.load_bias is not None:
            static_addr = runtime_addr - module.load_bias

        hex_static = "0x{:x}".format(static_addr)
        if hex_static in self.functions:
            fn = self.functions[hex_static]
            return {
                "status": "RESOLVED",
                "link_kind": LINK_KIND_FUNCTION_ADDRESS,
                "is_verified": True,
                "runtime_address": "0x{:x}".format(runtime_addr),
                "static_address": hex_static,
                "symbol_name": fn.get("name"),
                "source_file": fn.get("file"),
                "line_number": fn.get("line"),
                "link_basis": "mock_static_address_match",
            }

        if type_name:
            return {
                "status": "RESOLVED_TYPE_MATCH",
                "link_kind": LINK_KIND_TYPE_DEFINITION,
                "is_verified": True,
                "is_relationship_candidate": False,
                "runtime_address": "0x{:x}".format(runtime_addr),
                "static_address": hex_static,
                "type": type_name,
                "link_basis": "mock_type_definition_match",
                "relationship_limitation": "Type match establishes TYPE_DEFINITION only; does NOT prove function ownership or field write.",
            }

        return {
            "status": "UNRESOLVED_ADDRESS_NOT_FOUND",
            "link_kind": LINK_KIND_UNRESOLVED,
            "is_verified": False,
            "runtime_address": "0x{:x}".format(runtime_addr),
            "static_address": hex_static,
            "link_basis": None,
            "reason": "Address not found in mock symbols.",
        }


class DwarfStaticAnalysisProvider(StaticAnalysisProvider):
    """Host-side static analysis provider leveraging DWARF index and standard ELF utilities.

    Caches parsed symbol tables (`nm -C -n`), disassembled instruction lines (`objdump -d -C`),
    and static symbol reference lookups per `(abs_path, mtime_ns, size)` so that repeated
    calls during investigation stages never spawn duplicate binutils subprocesses.
    """

    _CACHE_LOCK = threading.Lock()
    _INFLIGHT_LOCKS: Dict[Tuple[str, int, int], threading.Lock] = {}
    _SYMBOLS_CACHE: Dict[Tuple[str, int, int], Tuple[Dict[str, Dict[str, Any]], Dict[int, Dict[str, Any]], Dict[str, Dict[str, Any]]]] = {}
    _DISASM_CACHE: Dict[Tuple[str, int, int], List[Tuple[str, str]]] = {}
    _REFS_CACHE: Dict[Tuple[Tuple[str, int, int], str], List[Dict[str, Any]]] = {}
    _PROVIDER_INSTANCES: Dict[Tuple[str, int, int], "DwarfStaticAnalysisProvider"] = {}

    @classmethod
    def clear_caches(cls) -> None:
        """Clear all cached static analysis tables (used in test teardown)."""
        with cls._CACHE_LOCK:
            cls._SYMBOLS_CACHE.clear()
            cls._DISASM_CACHE.clear()
            cls._REFS_CACHE.clear()
            cls._PROVIDER_INSTANCES.clear()

    def __init__(self, debug_artifact_path: Optional[str] = None):
        self.debug_artifact_path = os.path.abspath(debug_artifact_path) if debug_artifact_path else None
        self._dwarf_index: Optional[DwarfIndex] = None
        self._parsed_symbols: Dict[str, Dict[str, Any]] = {}
        self._functions_by_addr: Dict[int, Dict[str, Any]] = {}
        self._functions_by_name: Dict[str, Dict[str, Any]] = {}
        self._symbols_loaded: bool = False
        if self.debug_artifact_path and os.path.exists(self.debug_artifact_path):
            self._load_symbols()

    def _get_artifact_key(self) -> Optional[Tuple[str, int, int]]:
        if not self.debug_artifact_path or not os.path.exists(self.debug_artifact_path):
            return None
        try:
            st = os.stat(self.debug_artifact_path)
            return (self.debug_artifact_path, st.st_mtime_ns, st.st_size)
        except OSError:
            return None

    @classmethod
    def _get_inflight_lock(cls, key: Tuple[str, int, int]) -> threading.Lock:
        with cls._CACHE_LOCK:
            lock = cls._INFLIGHT_LOCKS.get(key)
            if lock is None:
                lock = threading.Lock()
                cls._INFLIGHT_LOCKS[key] = lock
            return lock

    def is_available(self) -> bool:
        return self.debug_artifact_path is not None and os.path.exists(self.debug_artifact_path)

    def get_provider_name(self) -> str:
        return "dwarf_static_analyzer"

    def _get_index(self) -> Optional[DwarfIndex]:
        if self._dwarf_index is None and self.debug_artifact_path and os.path.exists(self.debug_artifact_path):
            try:
                self._dwarf_index = DwarfIndexer.get_index(self.debug_artifact_path)
            except Exception:
                pass
        return self._dwarf_index

    def _load_symbols(self) -> None:
        if self._symbols_loaded:
            return
        art_key = self._get_artifact_key()
        if art_key is None:
            return

        with self._CACHE_LOCK:
            cached = self._SYMBOLS_CACHE.get(art_key)
            if cached is not None:
                self._parsed_symbols, self._functions_by_addr, self._functions_by_name = cached
                self._symbols_loaded = True
                return

        inflight = self._get_inflight_lock(art_key)
        with inflight:
            with self._CACHE_LOCK:
                cached = self._SYMBOLS_CACHE.get(art_key)
                if cached is not None:
                    self._parsed_symbols, self._functions_by_addr, self._functions_by_name = cached
                    self._symbols_loaded = True
                    return

            parsed_symbols: Dict[str, Dict[str, Any]] = {}
            functions_by_addr: Dict[int, Dict[str, Any]] = {}
            functions_by_name: Dict[str, Dict[str, Any]] = {}

            try:
                cmd = ["nm", "-C", "-n", self.debug_artifact_path]
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    errors="replace",
                    preexec_fn=_low_priority_preexec if hasattr(os, "nice") else None,
                )
                try:
                    assert proc.stdout is not None
                    for line in proc.stdout:
                        parts = line.strip().split(maxsplit=2)
                        if len(parts) >= 3:
                            try:
                                addr = int(parts[0], 16)
                                sym_type = parts[1]
                                name = parts[2]
                                entry = {
                                    "name": name,
                                    "address": addr,
                                    "hex_address": f"0x{addr:x}",
                                    "type": sym_type,
                                }
                                parsed_symbols[name] = entry
                                if sym_type in ("T", "t", "W", "w"):
                                    functions_by_addr[addr] = entry
                                    functions_by_name[name] = entry
                            except ValueError:
                                pass
                finally:
                    try:
                        proc.stdout.close()  # type: ignore[union-attr]
                    except Exception:
                        pass
                    proc.wait(timeout=15)
            except Exception:
                pass

            with self._CACHE_LOCK:
                self._SYMBOLS_CACHE[art_key] = (parsed_symbols, functions_by_addr, functions_by_name)
                self._parsed_symbols = parsed_symbols
                self._functions_by_addr = functions_by_addr
                self._functions_by_name = functions_by_name
                self._symbols_loaded = True

    def _get_cached_disassembly(self) -> List[Tuple[str, str]]:
        """Run `objdump -d -C` at most once per binary and cache compact (caller_fn, line) pairs
        filtered to user functions, enforcing a strict line budget (`DYNAMICSTATE_MAX_DISASM_LINES`)."""
        art_key = self._get_artifact_key()
        if art_key is None:
            return []

        with self._CACHE_LOCK:
            cached = self._DISASM_CACHE.get(art_key)
            if cached is not None:
                return cached

        inflight = self._get_inflight_lock(art_key)
        with inflight:
            with self._CACHE_LOCK:
                cached = self._DISASM_CACHE.get(art_key)
                if cached is not None:
                    return cached

            max_lines = int(os.environ.get("DYNAMICSTATE_MAX_DISASM_LINES", "150000"))
            records: List[Tuple[str, str]] = []
            current_fn: Optional[str] = None
            skip_fn: bool = False

            try:
                cmd = ["objdump", "-d", "-C", self.debug_artifact_path]  # type: ignore[list-item]
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    errors="replace",
                    preexec_fn=_low_priority_preexec if hasattr(os, "nice") else None,
                )
                try:
                    assert proc.stdout is not None
                    line_count = 0
                    for raw_line in proc.stdout:
                        line_count += 1
                        if line_count > max_lines:
                            try:
                                proc.terminate()
                            except Exception:
                                pass
                            break
                        line = raw_line.rstrip("\r\n")
                        if line.endswith(">:") and "<" in line:
                            idx = line.find("<")
                            current_fn = line[idx + 1:-2]
                            skip_fn = any(current_fn.startswith(p) for p in ("std::", "__", "_"))
                        elif current_fn and not skip_fn:
                            s_line = line.strip()
                            if s_line:
                                records.append((current_fn, s_line))
                finally:
                    try:
                        proc.stdout.close()  # type: ignore[union-attr]
                    except Exception:
                        pass
                    try:
                        proc.wait(timeout=5)
                    except Exception:
                        try:
                            proc.kill()
                        except Exception:
                            pass
            except Exception:
                records = []

            with self._CACHE_LOCK:
                self._DISASM_CACHE[art_key] = records
            return records

    def inspect_function(self, name_or_addr: Union[str, int], module: Optional[RuntimeModule] = None) -> Optional[Dict[str, Any]]:
        self._load_symbols()
        if isinstance(name_or_addr, int):
            if name_or_addr in self._functions_by_addr:
                return self._functions_by_addr[name_or_addr]
            # Find closest function entry point
            sorted_addrs = sorted(self._functions_by_addr.keys())
            for i, a in enumerate(sorted_addrs):
                if a <= name_or_addr:
                    next_a = sorted_addrs[i + 1] if i + 1 < len(sorted_addrs) else a + 0x1000
                    if name_or_addr < next_a:
                        fn = dict(self._functions_by_addr[a])
                        fn["offset"] = name_or_addr - a
                        return fn
            return None
        return self._functions_by_name.get(str(name_or_addr))

    def lookup_symbol(self, symbol_name: str, module: Optional[RuntimeModule] = None) -> Optional[Dict[str, Any]]:
        self._load_symbols()
        idx = self._get_index()
        if idx and symbol_name in idx.variables_by_name:
            vars_list = idx.variables_by_name[symbol_name]
            if vars_list:
                v = vars_list[0]
                t_name = idx.get_type_name(v.type_offset)
                return {
                    "name": v.name,
                    "type": t_name,
                    "link_time_address": v.link_time_address,
                    "hex_address": f"0x{v.link_time_address:x}" if v.link_time_address is not None else None,
                    "is_external": v.is_external,
                    "decl_file": v.decl_file,
                    "decl_line": v.decl_line,
                }

        if symbol_name in self._parsed_symbols:
            return self._parsed_symbols[symbol_name]
        return None

    def find_references(
        self,
        name_or_addr: Union[str, int],
        module: Optional[RuntimeModule] = None,
        disassembly_text: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        # Lightweight static reference discovery via cached objdump disassembly if available
        refs: List[Dict[str, Any]] = []
        sym_name = str(name_or_addr)
        if isinstance(name_or_addr, int):
            fn = self.inspect_function(name_or_addr)
            if fn:
                sym_name = fn.get("name", hex(name_or_addr))

        if disassembly_text is not None:
            current_fn = None
            sym_pattern = re.compile(rf"\b{re.escape(sym_name)}\b")
            for line in disassembly_text.splitlines():
                if line.endswith(">:") and "<" in line:
                    idx = line.find("<")
                    current_fn = line[idx + 1:-2]
                elif current_fn and sym_name != current_fn:
                    if any(current_fn.startswith(p) for p in ("std::", "__", "_")):
                        continue
                    if sym_pattern.search(line):
                        is_write = any(w in line for w in ("mov", "str", "stw", "stx", "="))
                        refs.append({
                            "caller_function": current_fn,
                            "reference_site": line.strip(),
                            "target": sym_name,
                            "link_kind": LINK_KIND_FIELD_WRITE_CANDIDATE if is_write else LINK_KIND_CALL_RELATIONSHIP,
                            "is_verified": False,
                            "is_candidate_only": True,
                            "confidence": "CANDIDATE",
                            "basis": "disassembly_text_match",
                            "limitation": "Disassembly text search establishes candidate reference only, not proof of verified call edge or field write.",
                        })
                        if len(refs) >= 20:
                            break
            return refs

        art_key = self._get_artifact_key()
        if art_key is None:
            return []

        ref_cache_key = (art_key, sym_name)
        with self._CACHE_LOCK:
            cached_refs = self._REFS_CACHE.get(ref_cache_key)
            if cached_refs is not None:
                return list(cached_refs)

        disasm_records = self._get_cached_disassembly()
        sym_pattern = re.compile(rf"\b{re.escape(sym_name)}\b")
        for current_fn, s_line in disasm_records:
            if sym_name == current_fn or sym_name not in s_line:
                continue
            if sym_pattern.search(s_line):
                is_write = any(w in s_line for w in ("mov", "str", "stw", "stx", "="))
                refs.append({
                    "caller_function": current_fn,
                    "reference_site": s_line,
                    "target": sym_name,
                    "link_kind": LINK_KIND_FIELD_WRITE_CANDIDATE if is_write else LINK_KIND_CALL_RELATIONSHIP,
                    "is_verified": False,
                    "is_candidate_only": True,
                    "confidence": "CANDIDATE",
                    "basis": "disassembly_text_match",
                    "limitation": "Disassembly text search establishes candidate reference only, not proof of verified call edge or field write.",
                })
                if len(refs) >= 20:
                    break

        with self._CACHE_LOCK:
            if len(self._REFS_CACHE) > 4096:
                self._REFS_CACHE.clear()
            self._REFS_CACHE[ref_cache_key] = list(refs)
        return refs

    def get_call_relationships(self, function_name: str, module: Optional[RuntimeModule] = None) -> Dict[str, Any]:
        refs = self.find_references(function_name, module)
        callers = list({r["caller_function"] for r in refs if "caller_function" in r})
        return {
            "function": function_name,
            "callers": callers,
            "callees": [],
            "status": "RESOLVED" if callers else "EMPTY",
        }

    def resolve_runtime_to_code(
        self,
        runtime_addr: int,
        module: Optional[RuntimeModule] = None,
        type_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Correlate a runtime memory address to static DWARF variables, types, or symbols."""
        if module is None:
            return {
                "status": "UNRESOLVED_NO_MODULE",
                "link_kind": LINK_KIND_UNRESOLVED,
                "is_verified": False,
                "runtime_address": "0x{:x}".format(runtime_addr),
                "link_basis": None,
                "reason": "No runtime module associated with the observation address.",
            }

        if module.build_id_status in (IDENTITY_MISMATCH, "MISMATCH"):
            return {
                "status": "UNRESOLVED_BUILD_ID_MISMATCH",
                "link_kind": LINK_KIND_UNRESOLVED,
                "is_verified": False,
                "runtime_address": "0x{:x}".format(runtime_addr),
                "module_id": module.module_id,
                "link_basis": None,
                "reason": "Module build ID mismatches debug image. Refusing to decode runtime address silently.",
            }

        if module.build_id_status not in (IDENTITY_VERIFIED_MATCH, "VERIFIED"):
            return {
                "status": "UNRESOLVED_IDENTITY_UNVERIFIED",
                "link_kind": LINK_KIND_UNRESOLVED,
                "is_verified": False,
                "runtime_address": "0x{:x}".format(runtime_addr),
                "module_id": module.module_id,
                "build_id_status": module.build_id_status,
                "link_basis": None,
                "reason": f"Module '{module.module_id}' identity cannot be reliably verified (status: {module.build_id_status}).",
            }

        if module.load_bias_status != "RESOLVED" or module.load_bias is None:
            return {
                "status": "UNRESOLVED_LOAD_BIAS",
                "link_kind": LINK_KIND_UNRESOLVED,
                "is_verified": False,
                "runtime_address": "0x{:x}".format(runtime_addr),
                "module_id": module.module_id,
                "link_basis": None,
                "reason": f"Module '{module.module_id}' has UNRESOLVED load bias.",
            }

        # Calculate static ELF address
        static_elf_addr = runtime_addr - module.load_bias
        hex_static = "0x{:x}".format(static_elf_addr)

        # 1. Check DWARF variables
        idx = self._get_index()
        if idx:
            for v in idx.variables:
                if v.link_time_address == static_elf_addr:
                    t_name = idx.get_type_name(v.type_offset)
                    return {
                        "status": "RESOLVED",
                        "link_kind": LINK_KIND_GLOBAL_VARIABLE,
                        "is_verified": True,
                        "runtime_address": "0x{:x}".format(runtime_addr),
                        "static_address": hex_static,
                        "module_id": module.module_id,
                        "symbol_name": v.name,
                        "type": t_name,
                        "link_basis": "dwarf_variable_link_time_address",
                        "decl_file": v.decl_file,
                        "decl_line": v.decl_line,
                        "is_external": v.is_external,
                    }

        # 2. Check function / symbol table
        fn = self.inspect_function(static_elf_addr, module)
        if fn:
            offset = fn.get("offset", 0)
            return {
                "status": "RESOLVED",
                "link_kind": LINK_KIND_FUNCTION_ADDRESS,
                "is_verified": True,
                "runtime_address": "0x{:x}".format(runtime_addr),
                "static_address": hex_static,
                "module_id": module.module_id,
                "symbol_name": fn.get("name"),
                "function_entry": fn.get("hex_address"),
                "function_offset": offset,
                "link_basis": "symbol_table_address_range",
            }

        # 3. Check type name match if address is on heap/stack (establishes TYPE_DEFINITION only!)
        if type_name and idx and type_name in idx.types_by_name:
            t_candidates = idx.types_by_name[type_name]
            if t_candidates:
                t = t_candidates[0]
                return {
                    "status": "RESOLVED_TYPE_MATCH",
                    "link_kind": LINK_KIND_TYPE_DEFINITION,
                    "is_verified": True,
                    "is_relationship_candidate": False,
                    "runtime_address": "0x{:x}".format(runtime_addr),
                    "static_address": hex_static,
                    "module_id": module.module_id,
                    "type": type_name,
                    "byte_size": t.byte_size,
                    "link_basis": "dwarf_type_definition_match",
                    "decl_file": t.decl_file,
                    "decl_line": t.decl_line,
                    "relationship_limitation": "Type match establishes TYPE_DEFINITION only; does NOT prove function ownership or field write.",
                }

        return {
            "status": "UNRESOLVED_ADDRESS_NOT_FOUND",
            "link_kind": LINK_KIND_UNRESOLVED,
            "is_verified": False,
            "runtime_address": "0x{:x}".format(runtime_addr),
            "static_address": hex_static,
            "module_id": module.module_id,
            "link_basis": None,
            "reason": f"Static address {hex_static} not found in debug symbols or functions.",
        }


def get_static_provider(
    backend: str = "dwarf",
    debug_artifact_path: Optional[str] = None,
) -> StaticAnalysisProvider:
    """Factory creating static analysis providers with instance reuse per artifact."""
    if backend == "mock":
        return MockStaticAnalysisProvider()
    elif backend == "dwarf":
        if debug_artifact_path and os.path.exists(debug_artifact_path):
            try:
                abs_p = os.path.abspath(debug_artifact_path)
                st = os.stat(abs_p)
                key = (abs_p, st.st_mtime_ns, st.st_size)
                with DwarfStaticAnalysisProvider._CACHE_LOCK:
                    inst = DwarfStaticAnalysisProvider._PROVIDER_INSTANCES.get(key)
                    if inst is not None:
                        return inst
                inst = DwarfStaticAnalysisProvider(abs_p)
                with DwarfStaticAnalysisProvider._CACHE_LOCK:
                    DwarfStaticAnalysisProvider._PROVIDER_INSTANCES[key] = inst
                return inst
            except OSError:
                pass
        return DwarfStaticAnalysisProvider(debug_artifact_path)
    return NullStaticAnalysisProvider()


def resolve_function_candidates(
    target_object: Dict[str, Any],
    target_field: Optional[Union[Dict[str, Any], str]] = None,
    snapshot: Optional[Dict[str, Any]] = None,
    static_provider: Optional[StaticAnalysisProvider] = None,
) -> Dict[str, Any]:
    """Correlate candidate functions to a target C++ object and field with explicit evidence levels.

    Assigns one of four grounded evidence tiers:
    - observed: Function was actively observed on a thread call stack in this runtime snapshot.
    - static: Function is a DWARF member function of the class or has a direct static reference in disassembly.
    - indirect: Function is a caller/callee of candidate functions in the static call graph.
    - unknown: Symbol match without verified DWARF debug information or unverified module Build ID.

    Crucial Caveat:
    DWARF member declaration lines specify struct memory layout only; they do NOT prove where
    this field was mutated at runtime.
    """
    obj_type = target_object.get("type") or target_object.get("canonical_type") or ""
    clean_type = re.sub(r"\b(struct|class|enum)\s+", "", str(obj_type)).strip()
    obj_id = target_object.get("object_id", "")
    obj_name = target_object.get("display_name") or target_object.get("semantic_name") or target_object.get("name") or obj_id

    field_name: Optional[str] = None
    field_decl_file: Optional[str] = None
    field_decl_line: Optional[int] = None
    if isinstance(target_field, dict):
        field_name = target_field.get("name")
        field_decl_file = target_field.get("decl_file")
        field_decl_line = target_field.get("decl_line")
    elif target_field:
        field_name = str(target_field)

    # If field_name was given as str, try finding it in target_object["fields"]
    if field_name and not field_decl_file:
        for f in target_object.get("fields", []):
            if isinstance(f, dict) and f.get("name") == field_name:
                field_decl_file = f.get("decl_file")
                field_decl_line = f.get("decl_line")
                break

    related_target = f"{clean_type}.{field_name}" if field_name else clean_type

    raw_candidates: List[FunctionCandidate] = []

    # 1. Check runtime snapshot execution context for OBSERVED evidence
    if snapshot:
        snap_dict = snapshot.to_dict() if hasattr(snapshot, "to_dict") else dict(snapshot)
        s_inner = snap_dict.get("snapshot", snap_dict)
        execution = snap_dict.get("execution") or s_inner.get("execution") or {}
        threads = execution.get("threads") or []
        for t in threads:
            t_id = t.get("thread_id", "unknown")
            frames = t.get("frames") or []
            for fr in frames:
                fn_name = fr.get("function") or fr.get("name")
                if not fn_name:
                    continue
                loc = fr.get("location") or fr.get("source_location")
                lvl = fr.get("level", 0)

                # Direct match to type or field
                is_type_match = bool(clean_type and (clean_type in fn_name or fn_name.startswith(f"{clean_type}::")))
                is_field_match = bool(field_name and field_name in fn_name)

                if is_type_match or is_field_match:
                    raw_candidates.append(FunctionCandidate(
                        function_name=fn_name,
                        source_location=loc,
                        related_target=related_target,
                        reason=f"Active on Thread {t_id} call stack (frame {lvl}) associated with {clean_type}",
                        evidence_level=EVIDENCE_LEVEL_OBSERVED,
                        basis_source="thread_call_stack",
                        limitations="Observed active on thread call stack; runtime mutation of this specific field remains unverified.",
                        thread_id=t_id,
                        frame_level=lvl,
                    ))
                else:
                    raw_candidates.append(FunctionCandidate(
                        function_name=fn_name,
                        source_location=loc,
                        related_target=f"Thread {t_id}",
                        reason=f"Active on Thread {t_id} call stack (frame {lvl}) during capture",
                        evidence_level=EVIDENCE_LEVEL_OBSERVED,
                        basis_source="thread_call_stack",
                        limitations="Observed active on thread call stack; structural association with target object is unverified.",
                        thread_id=t_id,
                        frame_level=lvl,
                    ))

    # 2. Check Static Provider (DWARF Index & Disassembly) for STATIC and INDIRECT evidence
    if static_provider and static_provider.is_available():
        # A) Check subprograms in DWARF index
        if hasattr(static_provider, "_get_index"):
            idx = static_provider._get_index()
            if idx and hasattr(idx, "subprograms"):
                for subp in idx.subprograms:
                    s_name = subp.name
                    if not s_name:
                        continue
                    loc = f"{subp.decl_file}:{subp.decl_line}" if (subp.decl_file and subp.decl_line) else None
                    if clean_type and (s_name.startswith(f"{clean_type}::") or f"::{clean_type}::" in s_name):
                        raw_candidates.append(FunctionCandidate(
                            function_name=s_name,
                            source_location=loc,
                            related_target=related_target,
                            reason=f"Class member function of '{clean_type}' declared in DWARF",
                            evidence_level=EVIDENCE_LEVEL_STATIC,
                            basis_source="dwarf_subprogram_scope",
                            limitations="Class member function declared in DWARF; runtime execution or field mutation in this snapshot is not verified.",
                        ))
                    elif s_name == clean_type:  # Constructor
                        raw_candidates.append(FunctionCandidate(
                            function_name=f"{clean_type}::{s_name}",
                            source_location=loc,
                            related_target=related_target,
                            reason=f"Constructor for class '{clean_type}' declared in DWARF",
                            evidence_level=EVIDENCE_LEVEL_STATIC,
                            basis_source="dwarf_subprogram_scope",
                            limitations="Constructor declared in DWARF; runtime execution in this snapshot is not verified.",
                        ))

                    elif not (subp.decl_file and ("/usr/include" in subp.decl_file or "/usr/lib" in subp.decl_file)):
                        s_lower = s_name.lower()
                        if not (s_name.startswith("_") or "<" in s_name or ">" in s_name or "~" in s_name or any(s_lower.startswith(p) for p in ("std::", "operator", "unique_ptr", "tuple", "allocator"))):
                            s_tokens = set(t.lower() for t in re.findall(r"[A-Za-z0-9]+", s_name) if len(t) >= 4)
                            target_tokens = set(t.lower() for t in re.findall(r"[A-Za-z0-9]+", f"{clean_type} {obj_name} {field_name}") if len(t) >= 4)
                            common = s_tokens & target_tokens
                            if common:
                                raw_candidates.append(FunctionCandidate(
                                    function_name=s_name,
                                    source_location=loc,
                                    related_target=related_target,
                                    reason=f"Candidate function referencing {', '.join(sorted(common))} in DWARF subprogram scope",
                                    evidence_level=EVIDENCE_LEVEL_STATIC,
                                    basis_source="dwarf_subprogram_scope",
                                    limitations="Correlated via DWARF subprogram symbols; runtime execution or field mutation in this snapshot is not verified.",
                                ))

        # B) Check Static References (disassembly)
        query_sym = field_name or clean_type
        if query_sym:
            refs = static_provider.find_references(query_sym)
            for r in refs:
                caller = r.get("caller_function")
                if caller:
                    raw_candidates.append(FunctionCandidate(
                        function_name=caller,
                        source_location=r.get("source_location"),
                        related_target=related_target,
                        reason=f"Static reference to '{query_sym}' in disassembly",
                        evidence_level=EVIDENCE_LEVEL_STATIC,
                        basis_source="disassembly_reference",
                        limitations="Static reference in binary disassembly; runtime execution of this instruction path is unverified.",
                    ))

        # C) Check Call relationships for callers of static candidates (INDIRECT candidates)
        static_cands = [c for c in raw_candidates if c.evidence_level == EVIDENCE_LEVEL_STATIC]
        for sc in static_cands[:10]:
            call_rel = static_provider.get_call_relationships(sc.function_name)
            for indirect_caller in call_rel.get("callers", []):
                if indirect_caller != sc.function_name:
                    raw_candidates.append(FunctionCandidate(
                        function_name=indirect_caller,
                        source_location=None,
                        related_target=sc.function_name,
                        reason=f"Caller of candidate function '{sc.function_name}' in static call graph",
                        evidence_level=EVIDENCE_LEVEL_INDIRECT,
                        basis_source="call_graph_reference",
                        limitations="Indirect relationship via static call graph; execution path unverified in this snapshot.",
                    ))

    # 3. Deduplication by function_name prioritizing tier: observed > static > indirect > unknown
    tier_order = {
        EVIDENCE_LEVEL_OBSERVED: 0,
        EVIDENCE_LEVEL_STATIC: 1,
        EVIDENCE_LEVEL_INDIRECT: 2,
        EVIDENCE_LEVEL_UNKNOWN: 3,
    }

    best_by_name: Dict[str, FunctionCandidate] = {}
    for cand in raw_candidates:
        fn = cand.function_name
        if fn not in best_by_name:
            best_by_name[fn] = cand
        else:
            cur_tier = tier_order.get(best_by_name[fn].evidence_level, 99)
            new_tier = tier_order.get(cand.evidence_level, 99)
            if new_tier < cur_tier:
                best_by_name[fn] = cand

    # Sort candidates by tier order, then function_name
    deduped = sorted(best_by_name.values(), key=lambda c: (tier_order.get(c.evidence_level, 99), c.function_name))

    return {
        "target_object_id": obj_id,
        "target_object_name": obj_name,
        "target_type": clean_type,
        "target_field": field_name,
        "field_decl_file": field_decl_file,
        "field_decl_line": field_decl_line,
        "layout_caveat": LAYOUT_MUTATION_CAVEAT,
        "candidates": [c.to_dict() for c in deduped],
        "total_candidates": len(deduped),
        "counts_by_tier": {
            EVIDENCE_LEVEL_OBSERVED: sum(1 for c in deduped if c.evidence_level == EVIDENCE_LEVEL_OBSERVED),
            EVIDENCE_LEVEL_STATIC: sum(1 for c in deduped if c.evidence_level == EVIDENCE_LEVEL_STATIC),
            EVIDENCE_LEVEL_INDIRECT: sum(1 for c in deduped if c.evidence_level == EVIDENCE_LEVEL_INDIRECT),
            EVIDENCE_LEVEL_UNKNOWN: sum(1 for c in deduped if c.evidence_level == EVIDENCE_LEVEL_UNKNOWN),
        },
    }
