"""
jcs.py — Strict JSON Canonicalization Scheme (RFC 8785).

Keys sorted lexicographically by UTF-16BE code unit sequence.
Numbers: IEEE-754 doubles, no NaN/Infinity, -0.0 → "0".
"""

import json
import math
from typing import Any


def _float_to_string(f: float) -> str:
    if math.isnan(f) or math.isinf(f):
        raise ValueError("NaN and Infinity are not permitted in JSON")
    if f == 0.0:
        return "0"
    s = json.dumps(f, allow_nan=False)
    if "e+" in s:
        s = s.replace("e+", "e")
    return s


def canonicalize(data: Any) -> bytes:
    """Returns the RFC 8785 canonical bytes of the given Python object."""
    if data is None:
        return b"null"
    if isinstance(data, bool):
        return b"true" if data else b"false"
    if isinstance(data, (int, float)):
        if isinstance(data, int):
            return str(data).encode("utf-8")
        return _float_to_string(data).encode("utf-8")
    if isinstance(data, str):
        return json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if isinstance(data, list):
        parts = [canonicalize(item) for item in data]
        return b"[" + b",".join(parts) + b"]"
    if isinstance(data, dict):

        def utf16_sort_key(s: str) -> bytes:
            return s.encode("utf-16-be")

        sorted_keys = sorted(data.keys(), key=utf16_sort_key)
        parts = []
        for key in sorted_keys:
            key_bytes = json.dumps(key, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            val_bytes = canonicalize(data[key])
            parts.append(key_bytes + b":" + val_bytes)
        return b"{" + b",".join(parts) + b"}"
    raise TypeError(f"Type {type(data)} not serializable to JCS")
