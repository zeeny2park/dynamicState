"""The type-size table of leak attribution must belong to the DWARF index it was built from."""
import unittest
from types import SimpleNamespace

from extractor import leak_attribution as la


def _analysis(types):
    tdie = {i: SimpleNamespace(tag="DW_TAG_structure_type", name=n, byte_size=sz) for i, (n, sz) in enumerate(types)}
    idx = SimpleNamespace(types_by_die=tdie)
    return SimpleNamespace(analyzer=SimpleNamespace(modules=[("main", idx)])), idx


class TypeSizeCacheIdentity(unittest.TestCase):
    def test_collected_index_does_not_leak_into_a_later_one(self):
        # 24-byte request -> 32-byte chunk; 40-byte request -> 48-byte chunk
        a1, idx1 = _analysis([("conn", 24)])
        self.assertEqual(la.candidate_types(a1, 32), ["struct conn"])
        old_id = id(idx1)
        a2 = idx2 = None
        for _ in range(500):
            del a1, idx1
            a2, idx2 = _analysis([("session", 40)])
            if id(idx2) == old_id:
                break   # CPython handed the collected index's id to the new one: the situation of the defect
            a1, idx1 = _analysis([("conn", 24)])
            la.candidate_types(a1, 32)
            old_id = id(idx1)
        # whether or not the id was reused in this run, the second index must see only its own types
        self.assertEqual(la.candidate_types(a2, 32), [])
        self.assertEqual(la.candidate_types(a2, 48), ["struct session"])

    def test_table_is_cached_per_index(self):
        a, idx = _analysis([("conn", 24)])
        la.candidate_types(a, 32)
        idx.types_by_die.clear()
        self.assertEqual(la.candidate_types(a, 32), ["struct conn"])   # cached on this very index


if __name__ == "__main__":
    unittest.main()
