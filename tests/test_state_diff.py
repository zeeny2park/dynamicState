import unittest

from extractor.state_diff import StateDiffEngine


def snapshot(objects, function="process_packet", pc="0x401200", thread_id=1):
    return {
        "schema_version": "0.3",
        "snapshot": {"snapshot_id": "S001", "pid": 1234, "binary": "./sample"},
        "execution": {
            "threads": [
                {
                    "thread_id": thread_id,
                    "frames": [{"level": 0, "function": function, "pc": pc}]
                }
            ]
        },
        "persistent": {"objects": objects}
    }


def obj(object_id, address, typ, fields):
    return {"object_id": object_id, "address": address, "type": typ, "fields": fields}


class StateDiffTests(unittest.TestCase):
    # Test 1: scalar changed (retry: 2 → 3)
    def test_1_scalar_changed(self):
        left = snapshot([obj("obj_0001", "0x1000", "Session", [{"name": "retry", "value": 2}])])
        right = snapshot([obj("obj_0001", "0x1000", "Session", [{"name": "retry", "value": 3}])])
        result = StateDiffEngine().diff(left, right)
        self.assertEqual(result.summary["value_changes"], 1)
        change = result.changes[0]
        self.assertEqual(change["kind"], "value_change")
        self.assertEqual(change["path"], "Session.retry")
        self.assertEqual(change["before"], 2)
        self.assertEqual(change["after"], 3)

    # Test 2: no change (identical snapshot → zero changes)
    def test_2_no_change_identical_snapshot(self):
        left = snapshot([
            obj("obj_0001", "0x1000", "Session", [{"name": "retry", "value": 2}]),
            obj("obj_0002", "0x2000", "Buffer", [{"name": "length", "value": 64}])
        ])
        right = snapshot([
            obj("obj_0001", "0x1000", "Session", [{"name": "retry", "value": 2}]),
            obj("obj_0002", "0x2000", "Buffer", [{"name": "length", "value": 64}])
        ])
        result = StateDiffEngine().diff(left, right)
        self.assertEqual(result.summary["value_changes"], 0)
        self.assertEqual(result.summary["objects_created"], 0)
        self.assertEqual(result.summary["objects_removed"], 0)
        self.assertEqual(result.summary["reference_changes"], 0)
        self.assertEqual(result.summary["execution_changes"], 0)
        self.assertEqual(result.summary["availability_changes"], 0)
        self.assertEqual(len(result.changes), 0)

    # Test 3: reference changed (obj_003 → obj_005)
    def test_3_reference_changed(self):
        left = snapshot([
            obj("obj_0001", "0x1000", "Session", [{"name": "buffer", "object_ref": "obj_0003"}]),
            obj("obj_0003", "0x3000", "Buffer", [])
        ])
        right = snapshot([
            obj("obj_0001", "0x1000", "Session", [{"name": "buffer", "object_ref": "obj_0005"}]),
            obj("obj_0005", "0x5000", "Buffer", [])
        ])
        result = StateDiffEngine().diff(left, right)
        self.assertEqual(result.summary["reference_changes"], 1)
        ref_change = next(c for c in result.changes if c["kind"] == "reference_change")
        self.assertEqual(ref_change["field"], "buffer")
        self.assertEqual(ref_change["before"], "obj_0003")
        self.assertEqual(ref_change["after"], "obj_0005")

    # Test 4: object created
    def test_4_object_created(self):
        left = snapshot([obj("obj_0001", "0x1000", "Session", [])])
        right = snapshot([
            obj("obj_0001", "0x1000", "Session", []),
            obj("obj_0005", "0x5000", "Buffer", [])
        ])
        result = StateDiffEngine().diff(left, right)
        self.assertEqual(result.summary["objects_created"], 1)
        change = next(c for c in result.changes if c["kind"] == "object_created")
        self.assertEqual(change["object_id"], "obj_0005")
        self.assertEqual(change["type"], "Buffer")

    # Test 5: object removed
    def test_5_object_removed(self):
        left = snapshot([
            obj("obj_0001", "0x1000", "Session", []),
            obj("obj_0005", "0x5000", "Buffer", [])
        ])
        right = snapshot([obj("obj_0001", "0x1000", "Session", [])])
        result = StateDiffEngine().diff(left, right)
        self.assertEqual(result.summary["objects_removed"], 1)
        change = next(c for c in result.changes if c["kind"] == "object_removed")
        self.assertEqual(change["object_id"], "obj_0005")

    # Test 6: execution function changed (process_packet → handle_error)
    def test_6_execution_function_changed(self):
        left = snapshot([], function="process_packet", pc="0x401200")
        right = snapshot([], function="handle_error", pc="0x401400")
        result = StateDiffEngine().diff(left, right)
        self.assertEqual(result.summary["execution_changes"], 1)
        change = result.changes[0]
        self.assertEqual(change["kind"], "execution_change")
        self.assertEqual(change["before_function"], "process_packet")
        self.assertEqual(change["after_function"], "handle_error")

    # Test 7: cycle graph (Session.parent → Session)
    def test_7_cycle_graph(self):
        left = snapshot([
            obj("obj_0001", "0x1000", "Session", [
                {"name": "parent", "object_ref": "obj_0001"},
                {"name": "retry", "value": 2}
            ])
        ])
        right = snapshot([
            obj("obj_0001", "0x1000", "Session", [
                {"name": "parent", "object_ref": "obj_0001"},
                {"name": "retry", "value": 3}
            ])
        ])
        result = StateDiffEngine().diff(left, right)
        self.assertEqual(result.summary["value_changes"], 1)
        self.assertEqual(result.summary["reference_changes"], 0)

    # Test 8: object ordering changed (no false positive)
    def test_8_object_ordering_changed_no_false_positive(self):
        o1 = obj("obj_0001", "0x1000", "A", [{"name": "v", "value": 1}])
        o2 = obj("obj_0002", "0x2000", "B", [{"name": "v", "value": 2}])
        o3 = obj("obj_0003", "0x3000", "C", [{"name": "v", "value": 3}])
        left = snapshot([o1, o2, o3])
        right = snapshot([o3, o1, o2])
        result = StateDiffEngine().diff(left, right)
        self.assertEqual(result.summary["value_changes"], 0)
        self.assertEqual(result.summary["objects_created"], 0)
        self.assertEqual(result.summary["objects_removed"], 0)
        self.assertEqual(len(result.changes), 0)

    # Test 9: unavailable value (availability change)
    def test_9_unavailable_value_availability_change(self):
        left = snapshot([
            obj("obj_0001", "0x1000", "Session", [{"name": "foo", "value": 1, "availability": "available"}])
        ])
        right = snapshot([
            obj("obj_0001", "0x1000", "Session", [{"name": "foo", "value": None, "availability": "unavailable"}])
        ])
        result = StateDiffEngine().diff(left, right)
        self.assertEqual(result.summary["availability_changes"], 1)
        change = result.changes[0]
        self.assertEqual(change["kind"], "availability_change")

    # Test 10: same address but different type (not merged into same logical object)
    def test_10_same_address_different_type_not_merged(self):
        left = snapshot([obj("obj_0001", "0x1000", "Session", [])])
        right = snapshot([obj("obj_0002", "0x1000", "Buffer", [])])
        result = StateDiffEngine().diff(left, right)
        self.assertEqual(result.summary["objects_removed"], 1)
        self.assertEqual(result.summary["objects_created"], 1)
        self.assertEqual(result.summary["value_changes"], 0)


if __name__ == "__main__":
    unittest.main()
