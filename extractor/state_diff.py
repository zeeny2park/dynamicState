"""Pure-Python, order-independent semantic snapshot diff."""

from dataclasses import asdict, dataclass, field
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple


@dataclass
class StateDiff:
    summary: Dict[str, int]
    changes: List[Dict[str, Any]] = field(default_factory=list)
    performance: Dict[str, Any] = field(default_factory=dict)
    trust_classification: str = "TRUSTED"
    diagnostics: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ObjectMatcher:
    """Base interface for cross-snapshot object identity matching."""

    def identity_key(self, obj: Dict[str, Any]) -> Any:
        raise NotImplementedError

    def match(self, before_object: Dict[str, Any], after_object: Dict[str, Any]) -> bool:
        raise NotImplementedError

    def metadata(self) -> Dict[str, Any]:
        return {
            "strategy": "unknown",
            "scope": "snapshot",
            "confidence": "observation"
        }


class AddressTypeObjectMatcher(ObjectMatcher):
    """Observation identity based on (address, canonical_type).

    address + canonical_type is used as snapshot-scoped observation identity.
    It is not a guaranteed allocation/lifetime identity across snapshots.
    """

    def identity_key(self, obj: Dict[str, Any]) -> Tuple[str, str]:
        return (str(obj.get("address")), str(obj.get("type")))

    def match(self, before_object: Dict[str, Any], after_object: Dict[str, Any]) -> bool:
        return self.identity_key(before_object) == self.identity_key(after_object)

    def metadata(self) -> Dict[str, Any]:
        return {
            "strategy": "address_type",
            "scope": "snapshot",
            "confidence": "observation"
        }


class LifecycleAwareObjectMatcher(ObjectMatcher):
    """Lifecycle-aware object identity matcher detecting address reuse and reallocation."""

    def identity_key(self, obj: Dict[str, Any]) -> Tuple[str, str]:
        return (str(obj.get("address")), str(obj.get("type")))

    def match(self, before_object: Dict[str, Any], after_object: Dict[str, Any]) -> bool:
        if str(before_object.get("address")) != str(after_object.get("address")):
            return False
        if str(before_object.get("type")) != str(after_object.get("type")):
            return False

        b_alloc = before_object.get("allocation_id") or before_object.get("generation") or before_object.get("lifecycle_id")
        a_alloc = after_object.get("allocation_id") or after_object.get("generation") or after_object.get("lifecycle_id")
        if b_alloc is not None and a_alloc is not None:
            return b_alloc == a_alloc
        return True

    def metadata(self) -> Dict[str, Any]:
        return {
            "strategy": "lifecycle_aware",
            "scope": "cross_snapshot",
            "confidence": "evidence_based"
        }


class StateDiffEngine:
    def __init__(self, matcher: Optional[ObjectMatcher] = None):
        self.matcher = matcher or AddressTypeObjectMatcher()

    def diff(self, before: Any, after: Any) -> StateDiff:
        start = time.monotonic()
        a, b = self._data(before), self._data(after)
        changes: List[Dict[str, Any]] = []
        fields_compared = 0
        objects_a = self._object_map(a)
        objects_b = self._object_map(b)
        identity_meta = self.matcher.metadata()

        addrs_a = {str(o.get("address")): o for o in objects_a.values() if o.get("address") not in (None, 0, "0", "None", "")}
        addrs_b = {str(o.get("address")): o for o in objects_b.values() if o.get("address") not in (None, 0, "0", "None", "")}

        for key in sorted(objects_b.keys() - objects_a.keys()):
            obj = objects_b[key]
            addr = obj.get("address")
            typ = obj.get("type")
            addr_str = str(addr)
            is_uncertain = (addr is None or typ is None or addr == 0 or addr_str in ("0", "None", ""))
            confidence = "uncertain" if is_uncertain else identity_meta.get("confidence", "low")

            is_addr_reuse = (addr_str in addrs_a)
            prior_type = addrs_a[addr_str].get("type") if is_addr_reuse else None

            chg_entry: Dict[str, Any] = {
                "kind": "object_created",
                "object_id": obj.get("object_id"),
                "type": obj.get("type"),
                "address": obj.get("address"),
                "identity": identity_meta,
                "identity_confidence": confidence,
            }
            if is_addr_reuse:
                chg_entry["address_reuse"] = True
                chg_entry["prior_type"] = prior_type
                chg_entry["identity_status"] = "ADDRESS_REUSED_DIFFERENT_TYPE"
            changes.append(chg_entry)

        for key in sorted(objects_a.keys() - objects_b.keys()):
            obj = objects_a[key]
            addr = obj.get("address")
            typ = obj.get("type")
            addr_str = str(addr)
            is_uncertain = (addr is None or typ is None or addr == 0 or addr_str in ("0", "None", ""))
            confidence = "uncertain" if is_uncertain else identity_meta.get("confidence", "low")
            is_addr_reuse = (addr_str in addrs_b)
            chg_entry = {
                "kind": "object_removed",
                "object_id": obj.get("object_id"),
                "type": obj.get("type"),
                "address": obj.get("address"),
                "identity": identity_meta,
                "identity_confidence": confidence,
            }
            if is_addr_reuse:
                chg_entry["address_reuse"] = True
                chg_entry["identity_status"] = "DESTROYED_AT_REUSED_ADDRESS"
            changes.append(chg_entry)

        for key in sorted(objects_a.keys() & objects_b.keys()):
            obj_a = objects_a[key]
            obj_b = objects_b[key]

            # Detect address reuse via allocation lifecycle counters
            alloc_a = obj_a.get("allocation_id") or obj_a.get("generation") or obj_a.get("lifecycle_id")
            alloc_b = obj_b.get("allocation_id") or obj_b.get("generation") or obj_b.get("lifecycle_id")

            if alloc_a is not None and alloc_b is not None and alloc_a != alloc_b:
                changes.append({
                    "kind": "object_reallocated_at_same_address",
                    "object_id": obj_b.get("object_id"),
                    "prior_object_id": obj_a.get("object_id"),
                    "type": obj_b.get("type"),
                    "address": obj_b.get("address"),
                    "before_allocation_id": alloc_a,
                    "after_allocation_id": alloc_b,
                    "address_reuse": True,
                    "identity_status": "DESTROYED_AND_REALLOCATED",
                    "identity_confidence": "high",
                    "identity": identity_meta,
                })
                continue

            storage = str(obj_a.get("storage") or obj_b.get("storage") or "").lower()
            if storage == "heap" and alloc_a is None and alloc_b is None:
                id_status = "IDENTITY_UNCERTAIN"
                id_conf = "uncertain"
            elif storage in ("global", "static"):
                id_status = "IDENTITY_VERIFIED"
                id_conf = "high"
            else:
                id_status = "IDENTITY_CONFIRMED" if alloc_a is not None else "IDENTITY_OBSERVATION"
                id_conf = "high" if alloc_a is not None else "low"

            added, compared = self._diff_object(obj_a, obj_b, objects_a, objects_b, identity_meta)
            for c in added:
                c["identity_status"] = id_status
                c["identity_confidence"] = id_conf
            changes.extend(added)
            fields_compared += compared
        changes.extend(self._execution_changes(a, b))

        # Evaluate snapshot completeness / quality to determine trust classification
        def _get_comp(snap: Any, data: Dict[str, Any]) -> str:
            c = getattr(snap, "completeness", None) or getattr(snap, "status", None)
            if c and str(c).upper() in ("INVALID", "FAILED", "PARTIAL"):
                return str(c).upper()
            c_dict = data.get("completeness") or data.get("status")
            if c_dict and str(c_dict).upper() in ("INVALID", "FAILED", "PARTIAL"):
                return str(c_dict).upper()

            prov = getattr(snap, "provenance", None) or data.get("provenance", {})
            obs = getattr(snap, "observation_metadata", None) or data.get("observation_metadata", {})

            if isinstance(prov, dict):
                id_contract = prov.get("identity_contract", {}) or {}
                if id_contract.get("identity_mismatch_detected") or id_contract.get("validity") == "INVALID":
                    return "INVALID"
                st = prov.get("capture_status") or id_contract.get("validity")
                if st and str(st).upper() in ("INVALID", "FAILED", "PARTIAL"):
                    return str(st).upper()
                if prov.get("map_enumeration", {}).get("status") in ("PARTIAL", "FAILED"):
                    return "PARTIAL"
                if prov.get("thread_enumeration", {}).get("status") in ("PARTIAL", "FAILED", "SUCCESS_EMPTY") or prov.get("thread_enumeration", {}).get("is_synthetic"):
                    return "PARTIAL"

            if isinstance(obs, dict):
                if obs.get("capture_status") in ("INVALID", "FAILED", "PARTIAL"):
                    return str(obs.get("capture_status")).upper()
                if obs.get("consistency_classification") == "NON_ATOMIC":
                    return "PARTIAL"
                if obs.get("map_enumeration", {}).get("status") in ("PARTIAL", "FAILED"):
                    return "PARTIAL"
                if obs.get("thread_enumeration", {}).get("status") in ("PARTIAL", "FAILED", "SUCCESS_EMPTY") or obs.get("thread_enumeration", {}).get("is_synthetic"):
                    return "PARTIAL"

            if c:
                return str(c).upper()
            if c_dict:
                return str(c_dict).upper()
            return "COMPLETE"

        comp_a = _get_comp(before, a)
        comp_b = _get_comp(after, b)

        diff_diagnostics: List[Dict[str, Any]] = []
        if comp_a == "INVALID" or comp_b == "INVALID":
            trust_classification = "UNTRUSTED_INVALID_CAPTURE"
            diff_diagnostics.append({
                "code": "DIFF_UNTRUSTED_INVALID_CAPTURE",
                "message": "Snapshot diff contains an INVALID capture snapshot (PID reuse or target identity mismatch). Comparison cannot produce verified facts.",
                "level": "ERROR"
            })
        elif comp_a == "FAILED" or comp_b == "FAILED":
            trust_classification = "UNTRUSTED_FAILED_CAPTURE"
            diff_diagnostics.append({
                "code": "DIFF_UNTRUSTED_FAILED_CAPTURE",
                "message": "Snapshot diff contains a FAILED capture snapshot. Comparison cannot produce verified facts.",
                "level": "ERROR"
            })
        elif comp_a == "PARTIAL" or comp_b == "PARTIAL":
            trust_classification = "PARTIALLY_TRUSTED"
            diff_diagnostics.append({
                "code": "DIFF_PARTIALLY_TRUSTED",
                "message": "Snapshot diff contains a PARTIAL capture snapshot. Missing fields or values may reflect partial capture.",
                "level": "WARNING"
            })
        else:
            trust_classification = "TRUSTED"

        for chg in changes:
            if trust_classification in ("UNTRUSTED_INVALID_CAPTURE", "UNTRUSTED_FAILED_CAPTURE"):
                chg["trust"] = "UNTRUSTED"
                chg["identity_confidence"] = "untrusted"
                chg["verified"] = False
            elif trust_classification == "PARTIALLY_TRUSTED":
                chg["trust"] = "PARTIAL"
                chg["identity_confidence"] = "uncertain"
                chg["capture_quality"] = "PARTIAL"
                chg["verified"] = False
            else:
                chg["trust"] = "TRUSTED"

        summary = {
            "total_changes": len(changes),
            "objects_created": sum(c["kind"] in ("object_created", "object_reallocated_at_same_address") for c in changes),
            "objects_removed": sum(c["kind"] in ("object_removed", "object_reallocated_at_same_address") for c in changes),
            "address_reuses": sum(bool(c.get("address_reuse")) for c in changes),
            "fields_added": sum(c["kind"] == "field_added" for c in changes),
            "fields_unavailable": sum(c["kind"] == "field_unavailable" for c in changes),
            "availability_changes": sum(c["kind"] == "availability_change" for c in changes),
            "value_changes": sum(c["kind"] == "value_change" for c in changes),
            "reference_changes": sum(c["kind"] == "reference_change" for c in changes),
            "execution_changes": sum(c["kind"] == "execution_change" for c in changes),
            "object_lifecycle_changes": sum(c["kind"] in ("object_created", "object_removed", "object_reallocated_at_same_address") for c in changes),
            "field_level_changes": sum(c["kind"] in ("field_added", "field_unavailable", "value_change", "reference_change") for c in changes),
            "observation_availability_changes": sum(c["kind"] in ("availability_change", "field_unavailable") for c in changes),
            "identity_ambiguities": sum(c.get("identity_confidence") == "uncertain" or c.get("identity_status") == "IDENTITY_UNCERTAIN" for c in changes),
        }
        return StateDiff(
            summary,
            changes,
            {
                "total_ms": round((time.monotonic() - start) * 1000, 3),
                "objects_compared": len(objects_a.keys() & objects_b.keys()),
                "fields_compared": fields_compared,
            },
            trust_classification=trust_classification,
            diagnostics=diff_diagnostics,
        )

    @staticmethod
    def _data(snapshot: Any) -> Dict[str, Any]:
        if snapshot is None:
            return {}
        if hasattr(snapshot, "to_dict"):
            return snapshot.to_dict()
        if isinstance(snapshot, dict):
            return snapshot
        return {}

    def _object_map(self, snapshot: Dict[str, Any]) -> Dict[Any, Dict[str, Any]]:
        persistent = snapshot.get("persistent") or {}
        objs = persistent.get("objects") if isinstance(persistent, dict) and "objects" in persistent else (snapshot.get("objects") or [])
        # Address+type is an observation identity, never a lifetime guarantee.
        return {self.matcher.identity_key(o): o for o in objs}


    def _diff_object(self, before, after, objects_a, objects_b, identity_meta):
        changes, compared = [], 0
        fields_a = {f.get("name"): f for f in before.get("fields", [])}
        fields_b = {f.get("name"): f for f in after.get("fields", [])}
        for name in sorted(set(fields_a) | set(fields_b)):
            left, right = fields_a.get(name), fields_b.get(name)
            if left is None and right is not None:
                path = "{}.{}".format(after.get("type"), name)
                changes.append({
                    "kind": "field_added",
                    "object_id": after.get("object_id"),
                    "type": after.get("type"),
                    "field": name,
                    "path": path,
                    "before": None,
                    "after": right.get("value"),
                    "identity": identity_meta,
                })
                continue
            if right is None and left is not None:
                path = "{}.{}".format(before.get("type"), name)
                changes.append({
                    "kind": "field_unavailable",
                    "object_id": before.get("object_id"),
                    "type": before.get("type"),
                    "field": name,
                    "path": path,
                    "before": left.get("value"),
                    "after": None,
                    "identity": identity_meta,
                    "reason": "Field absent or unreadable in subsequent observation.",
                })
                continue

            compared += 1
            path = "{}.{}".format(after.get("type"), name)
            if left.get("availability") != right.get("availability"):
                changes.append({"kind": "availability_change", "object_id": after.get("object_id"),
                                "path": path, "before": left.get("availability") or "available",
                                "after": right.get("availability") or "available",
                                "identity": identity_meta})
                continue
            left_ref = self._reference_key(left, objects_a)
            right_ref = self._reference_key(right, objects_b)
            if left_ref != right_ref:
                changes.append({"kind": "reference_change", "object_id": after.get("object_id"),
                                "type": after.get("type"), "field": name, "path": path,
                                "before": left.get("object_ref"), "after": right.get("object_ref"),
                                "identity": identity_meta})
            elif left.get("value") != right.get("value"):
                changes.append({"kind": "value_change", "object_id": after.get("object_id"),
                                "type": after.get("type"), "field": name, "path": path,
                                "before": left.get("value"), "after": right.get("value"),
                                "identity": identity_meta})
        return changes, compared

    def _reference_key(self, field, objects):
        ref = field.get("object_ref")
        if ref is None:
            return None
        target = next((obj for obj in objects.values() if obj.get("object_id") == ref), None)
        return self.matcher.identity_key(target) if target else ref

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
