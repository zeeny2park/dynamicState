"""On-disk encoding of an investigation session: each large observation payload is serialized once and stored once.

A session holds the same observation in several places: the collected evidence entry, the evidence record (twice:
``raw_details`` and ``raw_observation``), the check's ``actual_observations``, the methodology's copy of the check
and the conclusion's evidence chain.  On a many-thread target one thread observation is hundreds of KB, and the
check-level payloads (thread lists, call stacks) repeat across checks, so a plainly serialized session was tens of MB
of mostly repeated text.

``BlobInterner`` serializes each large value once (C encoder), keys it by the SHA-256 of that text and keeps the text;
the document carries ``{"__ds_blob__": key}`` in its place.  ``encode_document`` splices the already-serialized
texts into the file instead of encoding them again, so the file is still one plain JSON object (``json.load`` reads
it; the blob table is the top-level ``"blobs"`` object).  ``resolve_blobs`` puts the values back on load.  A session
file without ``"blobs"`` (written before this format) loads unchanged.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
from typing import Any, Dict, Tuple

BLOB_REF = "__ds_blob__"
BLOBS_KEY = "blobs"
# Values whose JSON text is shorter than this stay inline: a reference plus its table entry would not be smaller.
BLOB_MIN_CHARS = 2048

_SCALARS = (str, int, float, bool, type(None))


def persist_default(o: Any) -> Any:
    """JSON fallback of the session file.  Dataclasses become their fields (what ``asdict`` produces); anything else
    keeps the fallback the session file always used (``to_dict``, enum ``value``, ``str``)."""
    if dataclasses.is_dataclass(o) and not isinstance(o, type):
        return {f.name: getattr(o, f.name) for f in dataclasses.fields(o)}
    if hasattr(o, "to_dict"):
        return o.to_dict()
    if hasattr(o, "value"):
        return o.value
    return str(o)


def shallow_fields(obj: Any) -> Dict[str, Any]:
    """A dataclass instance as a dict of its fields without copying the values (the encoder walks them once)."""
    return {f.name: getattr(obj, f.name) for f in dataclasses.fields(obj)}


class BlobInterner:
    """Replaces large values by references to one stored copy (content-addressed, serialized once)."""

    def __init__(self, min_chars: int = BLOB_MIN_CHARS):
        self.min_chars = int(min_chars)
        self.blobs: Dict[str, str] = {}
        # id(value) -> (value, replacement): the same object seen again is not serialized again (the value is kept
        # referenced so its id cannot be reused while the document is built)
        self._memo: Dict[int, Tuple[Any, Any]] = {}
        self.serialized_chars = 0

    def value(self, v: Any) -> Any:
        if type(v) in _SCALARS:
            return v
        hit = self._memo.get(id(v))
        if hit is not None:
            return hit[1]
        text = json.dumps(v, default=persist_default)
        self.serialized_chars += len(text)
        if len(text) < self.min_chars:
            out = v
        else:
            key = hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()[:32]
            self.blobs.setdefault(key, text)
            out = {BLOB_REF: key}
        self._memo[id(v)] = (v, out)
        return out

    def fields(self, d: Any) -> Any:
        """An observation dict with each of its top-level values interned (keys stay readable in the document)."""
        if isinstance(d, dict):
            return {k: self.value(v) for k, v in d.items()}
        return self.value(d)


# Keys whose value is an observation payload (dict of named observations): each named observation is interned.
OBSERVATION_KEYS = frozenset({"raw_observation", "actual_observations", "raw_details", "details", "observation"})


def intern_observations(o: Any, it: BlobInterner) -> Any:
    """A copy of the document tree ``o`` in which every observation payload (a dict under one of
    ``OBSERVATION_KEYS``, wherever it occurs: evidence, checks, records, ledger, hypotheses) has its large values
    replaced by blob references.  Containers on the way are copied, never modified (the tree may share objects with
    the live session); the interned values themselves are not walked."""
    if dataclasses.is_dataclass(o) and not isinstance(o, type):
        o = shallow_fields(o)
    t = type(o)
    if t in _SCALARS:
        return o
    if isinstance(o, dict):
        out = {}
        for k, v in o.items():
            if type(v) in _SCALARS:
                out[k] = v
            elif k in OBSERVATION_KEYS and isinstance(v, dict):
                out[k] = it.fields(v)
            else:
                out[k] = intern_observations(v, it)
        return out
    if isinstance(o, (list, tuple)):
        return [v if type(v) in _SCALARS else intern_observations(v, it) for v in o]
    return o


def encode_document(doc: Dict[str, Any], blobs: Dict[str, str]) -> str:
    """The session file text: ``doc`` plus the blob table, each blob's text spliced in as already serialized."""
    if BLOBS_KEY in doc:
        raise ValueError(f"session document must not carry a top-level {BLOBS_KEY!r} key")
    body = json.dumps(doc, default=persist_default)
    if not blobs:
        return body
    table = ",".join(f"{json.dumps(k)}:{text}" for k, text in blobs.items())
    if body == "{}":
        return "{" + f'"{BLOBS_KEY}":{{{table}}}' + "}"
    return body[:-1] + f',"{BLOBS_KEY}":{{{table}}}' + "}"


def _resolve(o: Any, blobs: Dict[str, Any]) -> Any:
    if isinstance(o, dict):
        if len(o) == 1 and BLOB_REF in o:
            key = o[BLOB_REF]
            if not isinstance(key, str) or key not in blobs:
                raise ValueError(f"session file references a missing observation blob: {key!r}")
            return blobs[key]
        for k, v in o.items():
            if isinstance(v, (dict, list)):
                o[k] = _resolve(v, blobs)
        return o
    if isinstance(o, list):
        for i, v in enumerate(o):
            if isinstance(v, (dict, list)):
                o[i] = _resolve(v, blobs)
    return o


def resolve_blobs(data: Dict[str, Any]) -> Dict[str, Any]:
    """The loaded session document with every blob reference replaced by its value (in place; returns ``data``)."""
    if not isinstance(data, dict) or BLOBS_KEY not in data:
        return data
    blobs = data.pop(BLOBS_KEY)
    if not isinstance(blobs, dict):
        raise ValueError("session file blob table is not an object")
    return _resolve(data, blobs)
