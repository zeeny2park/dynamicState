"""Pure-Python, order-independent semantic snapshot diff."""

from dataclasses import asdict, dataclass, field
import time
from typing import Any, Dict, Iterable, List, Tuple


@dataclass
class StateDiff:
    summary: Dict[str, int]
    changes: List[Dict[str, Any]] = field(default_factory=list)
    performance: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class StateDiffEngine:
    def diff(self, before: Any, after: Any) -> StateDiff:
        start = time.monotonic()
        a, b = self._data(before), self._data(after)
        changes: List[Dict[str, Any]] = []
        fields_compared = 0
        objects_a = self._object_map(a)
        objects_b = self._object_map(b)
        for key in sorted(objects_b.keys() - objects_a.keys()):
            obj = objects_b[key]
            changes.append({"kind": "object_created", "object_id": obj.get("object_id"),
                            "type": obj.get("type"), "address": obj.get("address"),
                            "identity_confidence": "low"})
        for key in sorted(objects_a.keys() - objects_b.keys()):
            obj = objects_a[key]
            changes.append({"kind": "object_removed", "object_id": obj.get("object_id"),
                            "type": obj.get("type"), "address": obj.get("address"),
                            "identity_confidence": "low"})
        for key in sorted(objects_a.keys() & objects_b.keys()):
            added, compared = self._diff_object(objects_a[key], objects_b[key], objects_a, objects_b)
            changes.extend(added)
            fields_compared += compared
        changes.extend(self._execution_changes(a, b))
        summary = {
            "value_changes": sum(c["kind"] == "value_change" for c in changes),
            "availability_changes": sum(c["kind"] == "availability_change" for c in changes),
            "objects_created": sum(c["kind"] == "object_created" for c in changes),
            "objects_removed": sum(c["kind"] == "object_removed" for c in changes),
            "reference_changes": sum(c["kind"] == "reference_change" for c in changes),
            "execution_changes": sum(c["kind"] == "execution_change" for c in changes),
        }
        return StateDiff(summary, changes, {"total_ms": round((time.monotonic() - start) * 1000, 3),
                                             "objects_compared": len(objects_a.keys() & objects_b.keys()),
                                             "fields_compared": fields_compared})

    @staticmethod
    def _data(snapshot: Any) -> Dict[str, Any]:
        return snapshot.to_dict() if hasattr(snapshot, "to_dict") else snapshot

    @staticmethod
    def _object_map(snapshot: Dict[str, Any]) -> Dict[Tuple[str, str], Dict[str, Any]]:
        persistent = snapshot.get("persistent") or {}
        # Address+type is an observation identity, never a lifetime guarantee.
        return {(str(o.get("address")), str(o.get("type"))): o for o in persistent.get("objects", [])}

    def _diff_object(self, before, after, objects_a, objects_b):
        changes, compared = [], 0
        fields_a = {f.get("name"): f for f in before.get("fields", [])}
        fields_b = {f.get("name"): f for f in after.get("fields", [])}
        for name in sorted(set(fields_a) | set(fields_b)):
            left, right = fields_a.get(name), fields_b.get(name)
            if left is None or right is None:
                continue
            compared += 1
            path = "{}.{}".format(after.get("type"), name)
            if left.get("availability") != right.get("availability"):
                changes.append({"kind": "availability_change", "object_id": after.get("object_id"),
                                "path": path, "before": left.get("availability") or "available",
                                "after": right.get("availability") or "available"})
                continue
            left_ref = self._reference_key(left, objects_a)
            right_ref = self._reference_key(right, objects_b)
            if left_ref != right_ref:
                changes.append({"kind": "reference_change", "object_id": after.get("object_id"),
                                "type": after.get("type"), "field": name, "path": path,
                                "before": left.get("object_ref"), "after": right.get("object_ref")})
            elif left.get("value") != right.get("value"):
                changes.append({"kind": "value_change", "object_id": after.get("object_id"),
                                "type": after.get("type"), "field": name, "path": path,
                                "before": left.get("value"), "after": right.get("value")})
        return changes, compared

    @staticmethod
    def _reference_key(field, objects):
        ref = field.get("object_ref")
        if ref is None:
            return None
        target = next((obj for obj in objects.values() if obj.get("object_id") == ref), None)
        return (target.get("address"), target.get("type")) if target else ref

    @staticmethod
    def _execution_changes(before, after):
        def current(data):
            result = {}
            for thread in (data.get("execution") or {}).get("threads", []):
                frames = thread.get("frames") or []
                if frames:
                    result[thread.get("thread_id")] = {"frame": frames[0], "depth": len(frames)}
            return result
        left, right, changes = current(before), current(after), []
        for tid in sorted(set(left) | set(right), key=str):
            a_info, b_info = left.get(tid), right.get(tid)
            a = a_info["frame"] if a_info else None
            b = b_info["frame"] if b_info else None
            depth_a = a_info["depth"] if a_info else 0
            depth_b = b_info["depth"] if b_info else 0
            if a is None or b is None or (a.get("function"), a.get("pc")) != (b.get("function"), b.get("pc")):
                changes.append({
                    "kind": "execution_change",
                    "thread_id": tid,
                    "before_function": a.get("function") if a else None,
                    "after_function": b.get("function") if b else None,
                    "before": None if a is None else {"function": a.get("function"), "pc": a.get("pc"), "frame_depth": depth_a},
                    "after": None if b is None else {"function": b.get("function"), "pc": b.get("pc"), "frame_depth": depth_b}
                })
        return changes


if __name__ == "__main__":
    import argparse
    import json
    from extractor.snapshot import load_snapshot

    parser = argparse.ArgumentParser(description="Compute semantic diff between two state snapshots")
    parser.add_argument("--before", required=True, help="Path to before snapshot JSON")
    parser.add_argument("--after", required=True, help="Path to after snapshot JSON")
    parser.add_argument("--output", help="Optional output JSON file")
    args = parser.parse_args()

    s_before = load_snapshot(args.before)
    s_after = load_snapshot(args.after)
    diff_res = StateDiffEngine().diff(s_before, s_after)
    diff_dict = diff_res.to_dict()
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(diff_dict, f, indent=2, ensure_ascii=False)
            f.write("\n")
    print(json.dumps(diff_dict, indent=2, ensure_ascii=False))
