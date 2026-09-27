import json
import unittest
from extractor.runtime_state import ExecutionState, RuntimeState, VariableState
from extractor.serializer import to_json


class SerializerTests(unittest.TestCase):
    def test_null_and_unavailable_are_json_serializable(self):
        state = RuntimeState("0.1", {"pid": None}, ExecutionState(), [])
        result = json.loads(to_json(state))
        self.assertIsNone(result["process"]["pid"])
        self.assertEqual(result["objects"], [])

    def test_unavailable_and_invalid_fallback_fields_are_preserved(self):
        variable = VariableState("x", "int", None, availability="optimized_out", error="invalid value")
        encoded = json.loads(to_json(RuntimeState("0.1", {"pid": 1, "variable": variable}, ExecutionState(), [])))
        self.assertEqual(encoded["process"]["variable"]["availability"], "optimized_out")
        self.assertEqual(encoded["process"]["variable"]["error"], "invalid value")
