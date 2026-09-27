import unittest

from extractor.type_resolver import TypeResolver


class Gdb:
    TYPE_CODE_INT = 1; TYPE_CODE_FLT = 2; TYPE_CODE_BOOL = 3; TYPE_CODE_CHAR = 4
    TYPE_CODE_ENUM = 5; TYPE_CODE_PTR = 6; TYPE_CODE_REF = 7; TYPE_CODE_RVALUE_REF = 8
    TYPE_CODE_STRUCT = 9; TYPE_CODE_UNION = 10


class Type:
    def __init__(self, code, name, stripped=None): self.code, self.name, self._stripped = code, name, stripped
    def strip_typedefs(self): return self._stripped or self
    def __str__(self): return self.name


class TypeResolverTests(unittest.TestCase):
    def test_supported_type_kinds_and_typedef_canonicalization(self):
        resolver = TypeResolver(Gdb)
        self.assertEqual(resolver.kind(Type(Gdb.TYPE_CODE_INT, "int")), "primitive")
        self.assertEqual(resolver.kind(Type(Gdb.TYPE_CODE_ENUM, "State")), "enum")
        self.assertEqual(resolver.kind(Type(Gdb.TYPE_CODE_PTR, "Session *")), "pointer")
        self.assertEqual(resolver.kind(Type(Gdb.TYPE_CODE_REF, "Session &")), "reference")
        self.assertEqual(resolver.kind(Type(Gdb.TYPE_CODE_STRUCT, "Session")), "aggregate")
        underlying = Type(Gdb.TYPE_CODE_STRUCT, "Session")
        self.assertEqual(resolver.canonical_name(Type(Gdb.TYPE_CODE_STRUCT, "Alias", underlying)), "Session")
