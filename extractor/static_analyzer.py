"""Static analysis provider interface and adapters for evidence-linked code correlation.

Supports function inspection, symbol/reference lookup, and call relationship retrieval,
connecting runtime observations to static code only when module identity, Build ID,
and load bias provide a defensible basis.
"""

from abc import ABC, abstractmethod
import os
import re
import subprocess
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from .dwarf_indexer import DwarfIndex, DwarfIndexer
from .modules import ModuleAddressResolver, RuntimeModule


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

        if module and module.build_id_status == "MISMATCH":
            return {
                "status": "UNRESOLVED_BUILD_ID_MISMATCH",
                "runtime_address": "0x{:x}".format(runtime_addr),
                "link_basis": None,
                "reason": f"Module '{module.module_id}' build ID mismatches debug image.",
            }

        if module and module.load_bias_status != "RESOLVED":
            return {
                "status": "UNRESOLVED_LOAD_BIAS",
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
                "runtime_address": "0x{:x}".format(runtime_addr),
                "static_address": hex_static,
                "symbol_name": fn.get("name"),
                "source_file": fn.get("file"),
                "line_number": fn.get("line"),
                "link_basis": "mock_static_address_match",
            }

        return {
            "status": "UNRESOLVED_ADDRESS_NOT_FOUND",
            "runtime_address": "0x{:x}".format(runtime_addr),
            "static_address": hex_static,
            "link_basis": None,
            "reason": "Address not found in mock symbols.",
        }


class DwarfStaticAnalysisProvider(StaticAnalysisProvider):
    """Host-side static analysis provider leveraging DWARF index and standard ELF utilities."""

    def __init__(self, debug_artifact_path: Optional[str] = None):
        self.debug_artifact_path = os.path.abspath(debug_artifact_path) if debug_artifact_path else None
        self._dwarf_index: Optional[DwarfIndex] = None
        self._parsed_symbols: Dict[str, Dict[str, Any]] = {}
        self._functions_by_addr: Dict[int, Dict[str, Any]] = {}
        self._functions_by_name: Dict[str, Dict[str, Any]] = {}
        if self.debug_artifact_path and os.path.exists(self.debug_artifact_path):
            self._load_symbols()

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
        if not self.debug_artifact_path or not os.path.exists(self.debug_artifact_path):
            return

        # 1. Parse symbol table using nm -C
        try:
            cmd = ["nm", "-C", "-n", self.debug_artifact_path]
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if proc.returncode == 0:
                for line in proc.stdout.splitlines():
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
                            self._parsed_symbols[name] = entry
                            if sym_type in ("T", "t", "W", "w"):
                                self._functions_by_addr[addr] = entry
                                self._functions_by_name[name] = entry
                        except ValueError:
                            pass
        except Exception:
            pass

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

    def find_references(self, name_or_addr: Union[str, int], module: Optional[RuntimeModule] = None) -> List[Dict[str, Any]]:
        # Lightweight static reference discovery via objdump disassembly if available
        refs: List[Dict[str, Any]] = []
        sym_name = str(name_or_addr)
        if isinstance(name_or_addr, int):
            fn = self.inspect_function(name_or_addr)
            if fn:
                sym_name = fn.get("name", hex(name_or_addr))

        if not self.debug_artifact_path:
            return refs

        try:
            cmd = ["objdump", "-d", "-C", self.debug_artifact_path]
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if proc.returncode == 0:
                current_fn = None
                for line in proc.stdout.splitlines():
                    if line.endswith(">:") and "<" in line:
                        current_fn = line.split("<")[-1].rstrip(">:")
                    elif sym_name in line and current_fn and current_fn != sym_name:
                        refs.append({
                            "caller_function": current_fn,
                            "reference_site": line.strip(),
                            "target": sym_name,
                        })
                        if len(refs) >= 20:  # Bound result
                            break
        except Exception:
            pass
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
                "runtime_address": "0x{:x}".format(runtime_addr),
                "link_basis": None,
                "reason": "No runtime module associated with the observation address.",
            }

        if module.build_id_status == "MISMATCH":
            return {
                "status": "UNRESOLVED_BUILD_ID_MISMATCH",
                "runtime_address": "0x{:x}".format(runtime_addr),
                "module_id": module.module_id,
                "link_basis": None,
                "reason": f"Module build ID mismatches debug image. Refusing to decode runtime address silently.",
            }

        if module.load_bias_status != "RESOLVED" or module.load_bias is None:
            return {
                "status": "UNRESOLVED_LOAD_BIAS",
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
                "runtime_address": "0x{:x}".format(runtime_addr),
                "static_address": hex_static,
                "module_id": module.module_id,
                "symbol_name": fn.get("name"),
                "function_entry": fn.get("hex_address"),
                "function_offset": offset,
                "link_basis": "symbol_table_address_range",
            }

        # 3. Check type name heuristic match if address is on heap/stack
        if type_name and idx and type_name in idx.types_by_name:
            t_candidates = idx.types_by_name[type_name]
            if t_candidates:
                t = t_candidates[0]
                return {
                    "status": "RESOLVED_TYPE_MATCH",
                    "runtime_address": "0x{:x}".format(runtime_addr),
                    "static_address": hex_static,
                    "module_id": module.module_id,
                    "type": type_name,
                    "byte_size": t.byte_size,
                    "link_basis": "dwarf_type_definition_match",
                    "decl_file": t.decl_file,
                    "decl_line": t.decl_line,
                }

        return {
            "status": "UNRESOLVED_ADDRESS_NOT_FOUND",
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
    """Factory creating static analysis providers."""
    if backend == "mock":
        return MockStaticAnalysisProvider()
    elif backend == "dwarf":
        return DwarfStaticAnalysisProvider(debug_artifact_path)
    return NullStaticAnalysisProvider()
