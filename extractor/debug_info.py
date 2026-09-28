"""Debug information provider abstraction for offline semantic analysis (Phase 5.2).

Decouples DWARF extraction mechanisms (GDB batch mode, future native DWARF parser)
from the offline semantic analyzer, guaranteeing zero live process intervention.
"""

from abc import ABC, abstractmethod
import json
import os
import subprocess
from typing import Any, Dict, List, Optional

from .modules import RuntimeModule


class DebugInfoProvider(ABC):
    """Abstract interface for extracting DWARF symbols, types, and layouts."""

    @abstractmethod
    def load(self, module: RuntimeModule, debug_artifact_path: str) -> None:
        """Load DWARF context from the specified debug artifact."""
        pass

    @abstractmethod
    def get_symbols(self) -> List[Dict[str, Any]]:
        """Return list of global/static symbol dictionaries with static ELF addresses."""
        pass

    @abstractmethod
    def get_types(self) -> Dict[str, Any]:
        """Return map of type definitions, struct offsets, and enum members."""
        pass

    @abstractmethod
    def get_global_roots(self) -> List[Dict[str, Any]]:
        """Return list of global variables suitable as semantic reachability roots."""
        pass


class GdbDebugInfoProvider(DebugInfoProvider):
    """Offline DWARF provider utilizing GDB in batch mode without an inferior process.

    Strict Safety Guarantee:
    - Never attaches to or stops any live process.
    - Operates purely on the standalone debug image file on disk.
    """

    def __init__(self, debug_artifact_path: Optional[str] = None):
        self.debug_artifact_path: Optional[str] = None
        self._symbols: List[Dict[str, Any]] = []
        self._types: Dict[str, Any] = {}
        if debug_artifact_path:
            self.load(None, debug_artifact_path)

    def load(self, module: Optional[RuntimeModule], debug_artifact_path: str) -> None:
        """Extract symbols and type definitions via offline GDB batch execution."""
        abs_path = os.path.abspath(debug_artifact_path)
        if not os.path.exists(abs_path):
            raise FileNotFoundError(f"Debug artifact not found: {abs_path}")

        self.debug_artifact_path = abs_path

        # 1. Discover candidate global symbols using nm
        sym_list: List[str] = []
        try:
            cmd_nm = ["nm", "-g", "-C", "--defined-only", abs_path]
            proc_nm = subprocess.run(cmd_nm, capture_output=True, text=True, check=False)
            if proc_nm.returncode == 0:
                for line in proc_nm.stdout.splitlines():
                    parts = line.strip().split()
                    if len(parts) >= 3 and parts[1] in ("B", "D", "R", "b", "d", "r"):
                        name = parts[2]
                        if not name.startswith("_") and "::" not in name:
                            if name not in sym_list:
                                sym_list.append(name)
        except Exception:
            pass

        if not sym_list:
            sym_list = ["global_session", "file_session", "g_manager", "session"]

        sym_arg = json.dumps(sym_list)

        # 2. Run GDB batch script without inferior
        py_script = f"""
import gdb, json

sym_names = {sym_arg}
discovered_symbols = []
discovered_types = {{}}

for s_name in sym_names:
    try:
        sym = gdb.lookup_global_symbol(s_name)
        if not sym:
            sym = gdb.lookup_static_symbol(s_name)
        if sym:
            try:
                addr = int(sym.value().address)
            except Exception:
                addr = int(gdb.parse_and_eval('&' + s_name))
            discovered_symbols.append({{
                'name': s_name,
                'type': str(sym.type),
                'address': addr
            }})
            t = sym.type.strip_typedefs()
            if t.code in (gdb.TYPE_CODE_PTR, gdb.TYPE_CODE_REF):
                try:
                    target_t = t.target().strip_typedefs()
                    discovered_types[str(target_t)] = target_t
                except Exception:
                    pass
            discovered_types[str(t)] = t
    except Exception:
        pass

for extra in ['Session', 'Buffer', 'SessionState', 'Manager']:
    try:
        t = gdb.lookup_type(extra).strip_typedefs()
        discovered_types[extra] = t
    except Exception:
        pass

types_out = {{}}
for t_name, t in list(discovered_types.items()):
    try:
        clean_name = getattr(t, 'name', None) or getattr(t, 'tag', None) or str(t)
        if clean_name in types_out:
            continue
        if t.code in (gdb.TYPE_CODE_STRUCT, gdb.TYPE_CODE_UNION):
            fields = []
            for f in t.fields():
                if getattr(f, 'is_base_class', False):
                    continue
                fields.append({{
                    'name': f.name,
                    'type': str(f.type),
                    'offset': f.bitpos // 8 if f.bitpos is not None else 0,
                    'sizeof': getattr(f.type, 'sizeof', 0)
                }})
            types_out[clean_name] = {{
                'name': clean_name,
                'sizeof': t.sizeof,
                'code': 'aggregate',
                'fields': fields
            }}
        elif t.code == gdb.TYPE_CODE_ENUM:
            types_out[clean_name] = {{
                'name': clean_name,
                'sizeof': t.sizeof,
                'code': 'enum',
                'fields': [getattr(f, 'name', str(f)) for f in t.fields()]
            }}
    except Exception:
        pass

print('__DWARF_JSON_START__')
print(json.dumps({{'symbols': discovered_symbols, 'types': types_out}}))
print('__DWARF_JSON_END__')
"""
        cmd = ["gdb", "-q", "-nx", "-batch", abs_path, "-ex", f"python\n{py_script}"]
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            raise RuntimeError(f"GDB offline symbol extraction failed: {proc.stderr}")

        out = proc.stdout
        start_tag = "__DWARF_JSON_START__"
        end_tag = "__DWARF_JSON_END__"
        if start_tag not in out or end_tag not in out:
            raise RuntimeError(f"Failed to parse DWARF JSON output from GDB: {out}")

        json_str = out.split(start_tag, 1)[1].split(end_tag, 1)[0].strip()
        parsed = json.loads(json_str)
        self._symbols = parsed.get("symbols", [])
        self._types = parsed.get("types", {})

    def get_symbols(self) -> List[Dict[str, Any]]:
        return list(self._symbols)

    def get_types(self) -> Dict[str, Any]:
        return dict(self._types)

    def get_global_roots(self) -> List[Dict[str, Any]]:
        return [s for s in self._symbols if s.get("address") is not None]


class NativeDwarfDebugInfoProvider(DebugInfoProvider):
    """Interface placeholder for future native in-process DWARF parsing.

    Designed for subsequent phases to eliminate the GDB batch CLI subprocess.
    """

    def load(self, module: RuntimeModule, debug_artifact_path: str) -> None:
        raise NotImplementedError(
            "NativeDwarfDebugInfoProvider is not yet implemented in Phase 5.2. Use GdbDebugInfoProvider."
        )

    def get_symbols(self) -> List[Dict[str, Any]]:
        raise NotImplementedError()

    def get_types(self) -> Dict[str, Any]:
        raise NotImplementedError()

    def get_global_roots(self) -> List[Dict[str, Any]]:
        raise NotImplementedError()
