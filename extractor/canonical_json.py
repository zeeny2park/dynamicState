"""RFC 8785 (JSON Canonicalization Scheme - JCS) implementation for dynamicState.

Compliant with RFC 8785 / ECMAScript 6 (ES6) specifications:
- Character Encoding: Canonical JSON output is UTF-8 encoded without BOM.
- Whitespace: No whitespace characters outside of string literals.
- Object Key Ordering: Lexicographical order by UTF-16 code units (RFC 8785 Section 3.2.3),
  implemented via UTF-16 Big Endian code unit byte sequence (key.encode('utf-16-be')).
- Number Formatting:
  - Exact ECMAScript 6 (ES6) 7.1.12.1 ToString(Number) IEEE 754 double precision representation.
  - Non-finite numbers (NaN, +Infinity, -Infinity) are rejected with ValueError.
  - Negative zero (-0.0) is serialized as '0' (RFC 8785 Section 3.2.2).
  - Exponential notation boundaries: 1e-6 -> 0.000001, 1e-7 -> 1e-7, 1e20 -> 100000000000000000000, 1e21 -> 1e+21.
  - Exponents without leading zeros (1e+21, 1e-7).
  - Floating-point integers serialized without decimal point (1.0 -> 1).
  - Integer range validation: integers outside safe IEEE 754 range [-(2^53-1), 2^53-1] rejected with ValueError.
- Strings:
  - Standard JSON escaping for control characters (U+0000..U+001F), backslash, and double quote.
  - Literal UTF-8 characters for U+0020 and above.
  - Lone surrogate code points (U+D800..U+DFFF) rejected with ValueError.
- Strict Type Enforcement:
  - Object keys MUST be strings (TypeError on non-string keys).
  - Array elements MUST be lists (TypeError on tuples, sets, custom objects; no silent conversion).
  - Unsupported Python types reject fail-closed with TypeError.
"""

import json
import math
from typing import Any, List, Union


IEEE754_MAX_SAFE_INTEGER: int = 9007199254740991  # 2**53 - 1
IEEE754_MIN_SAFE_INTEGER: int = -9007199254740991  # -(2**53 - 1)


def convert2Es6Format(value: Union[int, float]) -> str:
    """Convert float/double or int to ECMAScript 6 ToString(Number) canonical format.

    Implements exact ES6 IEEE 754 shortest round-trip representation per RFC 8785 Section 3.2.2.3.
    Rejects integers outside the IEEE 754 double precision exact range [-(2^53-1), 2^53-1].
    """
    if isinstance(value, int) and not isinstance(value, bool):
        if not (IEEE754_MIN_SAFE_INTEGER <= value <= IEEE754_MAX_SAFE_INTEGER):
            raise ValueError(
                f"RFC 8785 rejects integer outside IEEE 754 safe integer range [-(2^53-1), 2^53-1]: {value}"
            )
        return str(value)

    fvalue = float(value)

    # Negative zero (-0.0) and zero are serialized as '0'
    if fvalue == 0:
        return "0"

    py_double = str(fvalue)

    # Detect NaN, Infinity, -Infinity
    if "n" in py_double:
        raise ValueError(f"RFC 8785 rejects non-finite number: {py_double}")

    py_sign = ""
    if py_double[0] == "-":
        py_sign = "-"
        py_double = py_double[1:]

    py_exp_str = ""
    py_exp_val = 0
    q = py_double.find("e")
    if q > 0:
        py_exp_str = py_double[q:]
        # Suppress leading zero on exponents (e.g., e-07 -> e-7, e+05 -> e+5)
        if py_exp_str[2:3] == "0":
            py_exp_str = py_exp_str[:2] + py_exp_str[3:]
        py_double = py_double[:q]
        py_exp_val = int(py_exp_str[1:])

    py_first = py_double
    py_dot = ""
    py_last = ""
    q = py_double.find(".")
    if q > 0:
        py_dot = "."
        py_first = py_double[:q]
        py_last = py_double[q + 1:]

    if py_last == "0":
        # Remove trailing .0
        py_dot = ""
        py_last = ""

    if 0 < py_exp_val < 21:
        # Integers up to 21 digits shown without scientific notation
        py_first += py_last
        py_last = ""
        py_dot = ""
        py_exp_str = ""
        pad = py_exp_val - len(py_first)
        while pad >= 0:
            pad -= 1
            py_first += "0"
    elif -7 < py_exp_val < 0:
        # Small numbers down to 1e-6 shown in fixed decimal notation (0.etc)
        py_last = py_first + py_last
        py_first = "0"
        py_dot = "."
        py_exp_str = ""
        pad = py_exp_val
        while pad < -1:
            pad += 1
            py_last = "0" + py_last

    return py_sign + py_first + py_dot + py_last + py_exp_str


def rfc8785_canonical_json(obj: Any) -> bytes:
    """Serializes a Python data structure to canonical JSON bytes per RFC 8785 (JCS).

    Raises:
        ValueError: If a non-finite float (NaN, inf, -inf), out-of-range integer, or lone surrogate is encountered.
        TypeError: If an object key is not a string, or an unsupported type (tuple, set, etc.) is encountered.
    """
    chunks: List[bytes] = []

    def _encode(v: Any) -> None:
        if v is None:
            chunks.append(b"null")
        elif isinstance(v, bool):
            # Must check bool before int because bool subclasses int in Python
            chunks.append(b"true" if v else b"false")
        elif isinstance(v, int):
            if not (IEEE754_MIN_SAFE_INTEGER <= v <= IEEE754_MAX_SAFE_INTEGER):
                raise ValueError(
                    f"RFC 8785 rejects integer outside IEEE 754 safe integer range [-(2^53-1), 2^53-1]: {v}"
                )
            chunks.append(str(v).encode("ascii"))
        elif isinstance(v, float):
            if math.isnan(v) or math.isinf(v):
                raise ValueError(f"RFC 8785 rejects non-finite float: {v}")
            chunks.append(convert2Es6Format(v).encode("ascii"))
        elif isinstance(v, str):
            for ch in v:
                if 0xD800 <= ord(ch) <= 0xDFFF:
                    raise ValueError(f"RFC 8785 rejects invalid Unicode surrogate code point: U+{ord(ch):04X}")
            chunks.append(json.dumps(v, ensure_ascii=False).encode("utf-8"))
        elif isinstance(v, list):
            chunks.append(b"[")
            for i, elem in enumerate(v):
                if i > 0:
                    chunks.append(b",")
                _encode(elem)
            chunks.append(b"]")
        elif isinstance(v, dict):
            chunks.append(b"{")
            # All keys must be strings and checked for surrogates
            for k in v.keys():
                if not isinstance(k, str):
                    raise TypeError(f"RFC 8785 requires all object keys to be strings, got {type(k).__name__}")
                for ch in k:
                    if 0xD800 <= ord(ch) <= 0xDFFF:
                        raise ValueError(f"RFC 8785 rejects invalid Unicode surrogate code point in key: U+{ord(ch):04X}")
            # RFC 8785 Section 3.2.3: Keys MUST be sorted in ascending order of their UTF-16 code units
            sorted_keys = sorted(v.keys(), key=lambda k: k.encode("utf-16-be"))
            for i, k in enumerate(sorted_keys):
                if i > 0:
                    chunks.append(b",")
                chunks.append(json.dumps(k, ensure_ascii=False).encode("utf-8"))
                chunks.append(b":")
                _encode(v[k])
            chunks.append(b"}")
        else:
            raise TypeError(f"RFC 8785 rejects unsupported type: {type(v).__name__} (no silent conversion)")

    _encode(obj)
    return b"".join(chunks)


def rfc8785_canonical_str(obj: Any) -> str:
    """Serializes a Python data structure to a canonical UTF-8 JSON string per RFC 8785."""
    return rfc8785_canonical_json(obj).decode("utf-8")
