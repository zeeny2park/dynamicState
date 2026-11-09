"""RFC 8785 (JSON Canonicalization Scheme - JCS) implementation for dynamicState.

Compliant with RFC 8785 / ECMAScript 6 (ES6) 7.1.12.1 ToString(Number) specifications:
- UTF-8 encoding without BOM.
- Whitespace: No whitespace characters outside of string literals.
- Object key sorting: Lexicographical order by UTF-8 bytes (RFC 8785 Section 3.2.3).
- Number formatting:
  - Non-finite numbers (NaN, +Infinity, -Infinity) are rejected with ValueError.
  - Negative zero (-0.0) is serialized as '0' (RFC 8785 Section 3.2.2).
  - Floating-point numbers are serialized according to ES6 shortest representation.
- Strings:
  - Standard JSON escaping for control characters (U+0000..U+001F), backslash, and double quote.
  - Literal UTF-8 characters for U+0020 and above.
- Strict type checking:
  - Rejects unsupported types (sets, functions, custom objects) with TypeError.
"""

import json
import math
from typing import Any, List, Union


def rfc8785_canonical_json(obj: Any) -> bytes:
    """Serializes a Python data structure to canonical JSON bytes per RFC 8785 (JCS).

    Raises:
        ValueError: If a non-finite float (NaN, inf, -inf) is encountered.
        TypeError: If an object key is not a string, or an unsupported type is encountered.
    """
    chunks: List[bytes] = []

    def _encode(v: Any) -> None:
        if v is None:
            chunks.append(b"null")
        elif isinstance(v, bool):
            # Check bool before int, since in Python isinstance(True, int) is True
            chunks.append(b"true" if v else b"false")
        elif isinstance(v, int):
            chunks.append(str(v).encode("ascii"))
        elif isinstance(v, float):
            if math.isnan(v) or math.isinf(v):
                raise ValueError(f"RFC 8785 rejects non-finite float: {v}")
            if v == 0.0:
                # RFC 8785 Section 3.2.2: Note that negative zero (-0) MUST be serialized as '0'
                chunks.append(b"0")
            elif v.is_integer() and abs(v) < 1e21:
                chunks.append(str(int(v)).encode("ascii"))
            else:
                s = repr(v)
                if "e" in s:
                    parts = s.split("e")
                    exp = int(parts[1])
                    sign = "+" if exp >= 0 else "-"
                    chunks.append(f"{parts[0]}e{sign}{abs(exp)}".encode("ascii"))
                else:
                    chunks.append(s.encode("ascii"))
        elif isinstance(v, str):
            chunks.append(json.dumps(v, ensure_ascii=False).encode("utf-8"))
        elif isinstance(v, (list, tuple)):
            chunks.append(b"[")
            for i, elem in enumerate(v):
                if i > 0:
                    chunks.append(b",")
                _encode(elem)
            chunks.append(b"]")
        elif isinstance(v, dict):
            chunks.append(b"{")
            # RFC 8785 Section 3.2.3: Keys sorted in ascending order of their UTF-8 bytes
            sorted_keys = sorted(v.keys(), key=lambda k: str(k).encode("utf-8"))
            for i, k in enumerate(sorted_keys):
                if not isinstance(k, str):
                    raise TypeError(f"RFC 8785 requires all object keys to be strings, got {type(k).__name__}")
                if i > 0:
                    chunks.append(b",")
                chunks.append(json.dumps(k, ensure_ascii=False).encode("utf-8"))
                chunks.append(b":")
                _encode(v[k])
            chunks.append(b"}")
        else:
            raise TypeError(f"RFC 8785 rejects unsupported type: {type(v).__name__}")

    _encode(obj)
    return b"".join(chunks)


def rfc8785_canonical_str(obj: Any) -> str:
    """Serializes a Python data structure to a canonical UTF-8 JSON string per RFC 8785."""
    return rfc8785_canonical_json(obj).decode("utf-8")
