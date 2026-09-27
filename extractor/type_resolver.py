"""DWARF/GDB type classification, isolated from graph traversal."""


class TypeResolver:
    """Classifies gdb.Type-like objects without parsing DWARF directly."""

    def __init__(self, gdb_module):
        self.gdb = gdb_module

    def strip_typedefs(self, gdb_type):
        current = gdb_type
        # strip_typedefs is provided by GDB and can fail for incomplete types.
        try:
            current = current.strip_typedefs()
        except Exception:
            pass
        return current

    def code(self, gdb_type):
        return self.strip_typedefs(gdb_type).code

    def canonical_name(self, gdb_type):
        resolved = self.strip_typedefs(gdb_type)
        name = getattr(resolved, "tag", None) or getattr(resolved, "name", None)
        return name or str(resolved)

    def display_name(self, gdb_type):
        # GDB commonly formats C++ pointers as ``Session *``. Keep schema
        # output stable and conventional without attempting a C++ demangler.
        return str(gdb_type).replace(" *", "*").replace(" &", "&")

    def kind(self, gdb_type):
        code = self.code(gdb_type)
        gdb = self.gdb
        codes = {
            getattr(gdb, "TYPE_CODE_INT", None): "primitive",
            getattr(gdb, "TYPE_CODE_FLT", None): "primitive",
            getattr(gdb, "TYPE_CODE_BOOL", None): "primitive",
            getattr(gdb, "TYPE_CODE_CHAR", None): "primitive",
            getattr(gdb, "TYPE_CODE_ENUM", None): "enum",
            getattr(gdb, "TYPE_CODE_PTR", None): "pointer",
            getattr(gdb, "TYPE_CODE_REF", None): "reference",
            getattr(gdb, "TYPE_CODE_RVALUE_REF", None): "reference",
            getattr(gdb, "TYPE_CODE_STRUCT", None): "aggregate",
            getattr(gdb, "TYPE_CODE_UNION", None): "aggregate",
        }
        return codes.get(code, "unknown")

    def target(self, gdb_type):
        try:
            return gdb_type.target()
        except Exception:
            return None
