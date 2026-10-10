"""
jcs.py — Canonical JSON for Sasana event hashes. Two named algorithms.

A session declares which one it uses in its SESSION_START payload, under the key
``canonicalization`` (hashed, so covered by the chain and any seal). A verifier reads that
declaration once and uses exactly that algorithm for every event; it never tries both.

``jcs-rfc8785``  (CANON_RFC8785)  Strict JSON Canonicalization Scheme, RFC 8785. Keys sorted
    by UTF-16BE code unit sequence. Numbers are IEEE-754 doubles serialized per ECMAScript
    Number::toString, no NaN/Infinity, -0.0 -> "0"; integers beyond +/-2**53 are rounded
    through a double. Writes by Sasana >= 2.0.0.

``legacy``  (CANON_LEGACY)  The serialization used by Sasana 1.0.0 and 1.1.0, kept ONLY so logs
    those versions wrote still verify. Identical to RFC 8785 except for numbers: floats are
    Python's repr() with "e+" shortened to "e" (``100.0``, ``1e-05``, ``1e16``), integers are
    exact at any size. A SESSION_START with no ``canonicalization`` field means legacy.
    Do not use it for new logs.

``canonicalize`` is RFC 8785. It is also what the commitment module and content hashes use.
"""

import decimal
import json
import math
from typing import Any


_MAX_SAFE_INT = 2**53

CANON_FIELD = "canonicalization"
CANON_RFC8785 = "jcs-rfc8785"
CANON_LEGACY = "legacy"
KNOWN_CANONICALIZATIONS = (CANON_RFC8785, CANON_LEGACY)


def _float_to_string(f: float) -> str:
    """
    ECMAScript Number::toString(10) as required by RFC 8785 section 3.2.2.3.

    Shortest round-trip digits come from repr(); layout follows the ES rules:
    plain decimal for 1e-6 <= |f| < 1e21, otherwise exponent form with an
    explicit sign ("1e+21", "1e-7").
    """
    if math.isnan(f) or math.isinf(f):
        raise ValueError("NaN and Infinity are not permitted in JSON")
    if f == 0.0:
        return "0"
    sign = "-" if f < 0 else ""
    d = decimal.Decimal(repr(abs(f)))
    _, digit_tuple, exp = d.as_tuple()
    digits = "".join(map(str, digit_tuple)).rstrip("0") or "0"
    # Position of the decimal point relative to the start of `digits`.
    n = len(digit_tuple) + exp
    k = len(digits)
    if k <= n <= 21:
        body = digits + "0" * (n - k)
    elif 0 < n <= 21:
        body = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        esign = "+" if e >= 0 else "-"
        mant = digits[0] if k == 1 else digits[0] + "." + digits[1:]
        body = f"{mant}e{esign}{abs(e)}"
    return sign + body


def canonicalize(data: Any) -> bytes:
    """Returns the RFC 8785 canonical bytes of the given Python object."""
    if data is None:
        return b"null"
    if isinstance(data, bool):
        return b"true" if data else b"false"
    if isinstance(data, (int, float)):
        if isinstance(data, int):
            if abs(data) <= _MAX_SAFE_INT:
                return str(data).encode("utf-8")
            # RFC 8785 numbers are IEEE-754 doubles; beyond 2**53 an int is
            # serialized as the double it rounds to, not as exact digits.
            return _float_to_string(float(data)).encode("utf-8")
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


# ---------------------------------------------------------------------------
# Legacy (Sasana 1.0.0 / 1.1.0) — frozen. Byte-for-byte what those releases emitted.
# ---------------------------------------------------------------------------


def _legacy_float_to_string(f: float) -> str:
    if math.isnan(f) or math.isinf(f):
        raise ValueError("NaN and Infinity are not permitted in JSON")
    if f == 0.0:
        return "0"
    s = json.dumps(f, allow_nan=False)
    if "e+" in s:
        s = s.replace("e+", "e")
    return s


def canonicalize_legacy(data: Any) -> bytes:
    """Canonical bytes exactly as Sasana 1.0.0 / 1.1.0 produced them. See module docstring."""
    if data is None:
        return b"null"
    if isinstance(data, bool):
        return b"true" if data else b"false"
    if isinstance(data, (int, float)):
        if isinstance(data, int):
            return str(data).encode("utf-8")
        return _legacy_float_to_string(data).encode("utf-8")
    if isinstance(data, str):
        return json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if isinstance(data, list):
        return b"[" + b",".join(canonicalize_legacy(item) for item in data) + b"]"
    if isinstance(data, dict):
        parts = []
        for key in sorted(data.keys(), key=lambda k: k.encode("utf-16-be")):
            key_bytes = json.dumps(key, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            parts.append(key_bytes + b":" + canonicalize_legacy(data[key]))
        return b"{" + b",".join(parts) + b"}"
    raise TypeError(f"Type {type(data)} not serializable to JCS")


def canonicalizer(name: str):
    """Return the canonicalize function for a declared algorithm name. Raises on unknown names."""
    if name == CANON_RFC8785:
        return canonicalize
    if name == CANON_LEGACY:
        return canonicalize_legacy
    raise ValueError(f"unknown canonicalization {name!r}")
