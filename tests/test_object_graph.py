import unittest

from extractor.object_graph import ObjectGraphBuilder
from extractor.type_resolver import TypeResolver


class Gdb:
    TYPE_CODE_INT = 1; TYPE_CODE_PTR = 2; TYPE_CODE_STRUCT = 3
    TYPE_CODE_FLT = TYPE_CODE_BOOL = TYPE_CODE_CHAR = TYPE_CODE_ENUM = TYPE_CODE_REF = TYPE_CODE_RVALUE_REF = TYPE_CODE_UNION = -1


class Type:
    def __init__(self, code, name): self.code, self.name = code, name
    def strip_typedefs(self): return self
    def __str__(self): return self.name


class Value:
    def __init__(self, typ, address, fields=None, target=None, scalar=0):
        self.type, self.address, self.fields, self.target, self.scalar = typ, address, fields or {}, target, scalar


class Backend:
    def value_type(self, v): return v.type
    def value_address(self, v): return v.address
    def object_address(self, v): return v.address
    def primitive_value(self, v, kind): return v.scalar if kind == "primitive" else None
    def pointer_text(self, v): return "0xdead"
    def dereference(self, v): return (v.target, None)
    def availability(self, e): return "unavailable"
    def fields(self, v):
        for n, child in v.fields.items(): yield {"name": n, "offset": 0, "value": child}


class ObjectGraphTests(unittest.TestCase):
    def test_identity_and_cycle_are_deduplicated(self):
        struct, ptr = Type(Gdb.TYPE_CODE_STRUCT, "Node"), Type(Gdb.TYPE_CODE_PTR, "Node*")
        node = Value(struct, "0x100")
        node.fields["self"] = Value(ptr, "0x108", target=node)
        graph = ObjectGraphBuilder(Backend(), TypeResolver(Gdb))
        first = graph.variable("a", Value(ptr, "0x200", target=node))
        second = graph.variable("b", Value(ptr, "0x208", target=node))
        self.assertEqual(first.object_ref, "obj_0001")
        self.assertEqual(second.object_ref, "obj_0001")
        self.assertEqual(len(graph.objects), 1)
        self.assertEqual(graph.objects[0].fields[0].object_ref, "obj_0001")

    def test_recursion_limit_does_not_create_deeper_objects(self):
        struct, ptr = Type(Gdb.TYPE_CODE_STRUCT, "Node"), Type(Gdb.TYPE_CODE_PTR, "Node*")
        second = Value(struct, "0x101")
        first = Value(struct, "0x100", {"next": Value(ptr, "0x108", target=second)})
        graph = ObjectGraphBuilder(Backend(), TypeResolver(Gdb), max_object_depth=1)
        graph.variable("root", Value(ptr, "0x200", target=first))
        self.assertEqual(len(graph.objects), 1)
        self.assertIsNone(graph.objects[0].fields[0].object_ref)

    def test_root_metadata_reuses_an_existing_object(self):
        struct, ptr = Type(Gdb.TYPE_CODE_STRUCT, "Node"), Type(Gdb.TYPE_CODE_PTR, "Node*")
        node = Value(struct, "0x100")
        graph = ObjectGraphBuilder(Backend(), TypeResolver(Gdb))
        variable = graph.variable("global_node", Value(ptr, "0x200", target=node))
        graph.add_root("global_node", "global", variable)
        self.assertEqual(graph.roots[0].object_ref, "obj_0001")
        self.assertEqual(len(graph.objects), 1)

    def test_null_pointer_has_a_null_object_reference(self):
        ptr = Type(Gdb.TYPE_CODE_PTR, "Node*")
        graph = ObjectGraphBuilder(Backend(), TypeResolver(Gdb))
        null = Value(ptr, "0x200", target=None)
        variable = graph.variable("maybe_node", null)
        self.assertIsNone(variable.object_ref)
