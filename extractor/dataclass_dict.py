"""``dataclasses.asdict`` with the same result, several times faster on large nested observations.

``asdict`` walks every value through a generic recursive function that re-dispatches on type for each element.  An
evidence record carries per-thread observations (hundreds of dicts with dozens of scalars each) and every investigation
step re-serialises all records, so that walk was a large share of a many-thread diagnosis.  This version copies plain
containers with a tight loop and treats scalars as leaves; dataclass instances become dicts, tuples stay tuples, and
nothing is shared with the source (same copy semantics as ``asdict``).
"""

from __future__ import annotations

import dataclasses
from typing import Any, Dict

_SCALARS = (str, int, float, bool, type(None), bytes)


def _copy(o: Any) -> Any:
    t = type(o)
    if t in _SCALARS:
        return o
    if t is dict:
        return {k: (v if type(v) in _SCALARS else _copy(v)) for k, v in o.items()}
    if t is list:
        return [(v if type(v) in _SCALARS else _copy(v)) for v in o]
    if dataclasses.is_dataclass(o) and not isinstance(o, type):
        return {f.name: _copy(getattr(o, f.name)) for f in dataclasses.fields(o)}
    if t is tuple:
        return tuple(_copy(v) for v in o)
    if isinstance(o, tuple) and hasattr(o, "_fields"):  # namedtuple
        return t(*[_copy(v) for v in o])
    if isinstance(o, dict):
        return t((_copy(k), _copy(v)) for k, v in o.items())
    if isinstance(o, (list, tuple)):
        return t(_copy(v) for v in o)
    import copy
    return copy.deepcopy(o)


def asdict(obj: Any) -> Dict[str, Any]:
    """Drop-in for ``dataclasses.asdict`` (instances only)."""
    if not (dataclasses.is_dataclass(obj) and not isinstance(obj, type)):
        raise TypeError("asdict() should be called on dataclass instances")
    return _copy(obj)
