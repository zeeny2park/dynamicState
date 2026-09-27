import unittest
from typing import Dict

from extractor.mutation import MutationResult
from extractor.runtime_controller import GdbRuntimeController
from extractor.runtime_state import FieldState, ObjectState, PersistentState, RuntimeState, ExecutionState
from extractor.snapshot import RuntimeSnapshot


class MockType:
    def __init__(self, code: int, name: str, sizeof: int = 4, fields=None):
        self.code = code
        self.name = name
        self.sizeof = sizeof
        self._fields = fields or []

    def strip_typedefs(self):
        return self

    def pointer(self):
        return MockType(MockGdb.TYPE_CODE_PTR, self.name + "*", sizeof=8)

    def fields(self):
        return self._fields

    def __str__(self):
        return self.name


class MockField:
    def __init__(self, name: str, type_obj: MockType, bitpos: int = 0):
        self.name = name
        self.type = type_obj
        self.bitpos = bitpos
        self.is_base_class = False


class MockValue:
    def __init__(self, typ: MockType, val, address: str = "0x1000", fields: Dict[str, "MockValue"] = None):
        self.type = typ
        self.val = val
        self.address = address
        self.field_dict = fields or {}

    def __getitem__(self, name: str) -> "MockValue":
        if name not in self.field_dict:
            raise KeyError(name)
        return self.field_dict[name]

    def assign(self, new_val) -> None:
        if isinstance(new_val, MockValue):
            self.val = new_val.val
        else:
            self.val = new_val

    def cast(self, target_type: MockType) -> "MockValue":
        return MockValue(target_type, self.val, self.address, self.field_dict)

    def dereference(self) -> "MockValue":
        return self

    def __int__(self) -> int:
        return int(self.val)

    def __float__(self) -> float:
        return float(self.val)

    def __str__(self) -> str:
        return str(self.val)


class MockThread:
    def is_stopped(self) -> bool:
        return True

    def switch(self) -> None:
        pass


class MockGdb:
    TYPE_CODE_INT = 1
    TYPE_CODE_FLT = 2
    TYPE_CODE_BOOL = 3
    TYPE_CODE_CHAR = 4
    TYPE_CODE_ENUM = 5
    TYPE_CODE_PTR = 6
    TYPE_CODE_REF = 7
    TYPE_CODE_RVALUE_REF = 8
    TYPE_CODE_STRUCT = 9
    TYPE_CODE_UNION = 10

    def __init__(self):
        self._types: Dict[str, MockType] = {}
        self.thread = MockThread()

    def selected_thread(self):
        return self.thread

    def lookup_type(self, name: str):
        if name in self._types:
            return self._types[name]
        for prefix in ("struct ", "class "):
            if name.startswith(prefix) and name[len(prefix):] in self._types:
                return self._types[name[len(prefix):]]
        raise RuntimeError("type not found: " + name)

    def Value(self, val):
        if isinstance(val, bool):
            return MockValue(MockType(self.TYPE_CODE_BOOL, "bool", 1), val)
        elif isinstance(val, int):
            return MockValue(MockType(self.TYPE_CODE_INT, "int", 4), val)
        elif isinstance(val, float):
            return MockValue(MockType(self.TYPE_CODE_FLT, "double", 8), val)
        return MockValue(MockType(self.TYPE_CODE_INT, "unknown", 4), val)

    def parse_and_eval(self, expr: str):
        if expr in ("SessionState::ERROR", "ERROR"):
            return MockValue(self._types["SessionState"], "SessionState::ERROR")
        if expr in ("SessionState::CONNECTED", "CONNECTED"):
            return MockValue(self._types["SessionState"], "SessionState::CONNECTED")
        raise RuntimeError("cannot parse: " + expr)


class MutationTests(unittest.TestCase):
    def setUp(self):
        self.gdb = MockGdb()
        t_uint32 = MockType(MockGdb.TYPE_CODE_INT, "uint32_t", 4)
        t_uint8 = MockType(MockGdb.TYPE_CODE_INT, "uint8_t", 1)
        t_bool = MockType(MockGdb.TYPE_CODE_BOOL, "bool", 1)
        t_enum = MockType(MockGdb.TYPE_CODE_ENUM, "SessionState", 4)
        t_buf_ptr = MockType(MockGdb.TYPE_CODE_PTR, "Buffer*", 8)
        t_session = MockType(MockGdb.TYPE_CODE_STRUCT, "Session", 24, [
            MockField("retry", t_uint32, 0),
            MockField("state", t_enum, 32),
            MockField("flagged", t_bool, 64),
            MockField("priority", t_uint8, 72),
            MockField("buffer", t_buf_ptr, 96),
        ])
        for t in (t_uint32, t_uint8, t_bool, t_enum, t_buf_ptr, t_session):
            self.gdb._types[t.name] = t

        self.session_value = MockValue(t_session, None, address="0x1000", fields={
            "retry": MockValue(t_uint32, 2, address="0x1000"),
            "state": MockValue(t_enum, "SessionState::CONNECTED", address="0x1004"),
            "flagged": MockValue(t_bool, False, address="0x1008"),
            "priority": MockValue(t_uint8, 7, address="0x1009"),
            "buffer": MockValue(t_buf_ptr, "0x2000", address="0x1010"),
        })

        self.controller = GdbRuntimeController(self.gdb)
        # Mock _runtime_object to return self.session_value
        self.controller._runtime_object = lambda address, type_name: self.session_value

        session_obj = ObjectState(
            object_id="obj_0001",
            type="Session",
            address="0x1000",
            storage="heap",
            fields=[
                FieldState("retry", "uint32_t", 0, 2),
                FieldState("state", "SessionState", 4, "SessionState::CONNECTED"),
                FieldState("flagged", "bool", 8, False),
                FieldState("priority", "uint8_t", 9, 7),
                FieldState("buffer", "Buffer*", 16, "0x2000"),
            ]
        )
        runtime_state = RuntimeState(
            schema_version="0.2",
            process={"pid": 1234, "binary": "sample"},
            execution=ExecutionState(),
            objects=[session_obj],
            persistent=PersistentState(objects=[session_obj])
        )
        self.controller._latest = RuntimeSnapshot.from_runtime_state(runtime_state, "S001")

    # Test 1: uint32 mutation (retry: 2 → 3)
    def test_1_uint32_mutation(self):
        res = self.controller.mutate("obj_0001", "retry", 3)
        self.assertTrue(res.success)
        self.assertEqual(res.before, 2)
        self.assertEqual(res.after, 3)
        self.assertEqual(res.field, "retry")

    # Test 2: enum mutation (state: CONNECTED → ERROR)
    def test_2_enum_mutation(self):
        res = self.controller.mutate("obj_0001", "state", "ERROR")
        self.assertTrue(res.success)
        self.assertEqual(res.after, "SessionState::ERROR")

    # Test 3: bool mutation (sample bool field flagged)
    def test_3_bool_mutation(self):
        res = self.controller.mutate("obj_0001", "flagged", True)
        self.assertTrue(res.success)
        self.assertEqual(res.after, True)

    # Test 4: invalid type (retry = "hello" → TYPE_CONVERSION_ERROR)
    def test_4_invalid_type(self):
        res = self.controller.mutate("obj_0001", "retry", "hello")
        self.assertFalse(res.success)
        self.assertEqual(res.error["code"], "TYPE_CONVERSION_ERROR")

    # Test 5: out-of-range (uint8_t field = 999 → RANGE_ERROR)
    def test_5_out_of_range(self):
        res = self.controller.mutate("obj_0001", "priority", 999)
        self.assertFalse(res.success)
        self.assertEqual(res.error["code"], "RANGE_ERROR")

    # Test 6: NULL pointer (pointer field를 NULL로 변경)
    def test_6_null_pointer_mutation(self):
        res = self.controller.mutate("obj_0001", "buffer", "null")
        self.assertTrue(res.success)
        self.assertEqual(res.after, "0x0")

    # Test 7: nonexistent field (Session.invalid_field → FIELD_NOT_FOUND)
    def test_7_nonexistent_field(self):
        res = self.controller.mutate("obj_0001", "invalid_field", 1)
        self.assertFalse(res.success)
        self.assertEqual(res.error["code"], "FIELD_NOT_FOUND")

    # Test 8: ambiguous path (여러 Session이 존재할 때: Session.retry → AMBIGUOUS_OBJECT)
    def test_8_ambiguous_path(self):
        session_obj2 = ObjectState(
            object_id="obj_0002",
            type="Session",
            address="0x3000",
            storage="heap",
            fields=[]
        )
        self.controller._latest.persistent.objects.append(session_obj2)
        res = self.controller.mutate(path="Session.retry", value=3)
        self.assertFalse(res.success)
        self.assertEqual(res.error["code"], "AMBIGUOUS_OBJECT")


if __name__ == "__main__":
    unittest.main()
