"""
sasana._utils — Shared internal utilities.
"""

from __future__ import annotations

import hashlib
from typing import Any

from sasana.jcs import canonicalize as jcs_canonicalize


def content_hash(value: Any) -> str:
    """
    SHA-256 of a value for use in event payloads.

    dicts and lists are serialized via RFC 8785 JCS for deterministic key
    ordering. str uses UTF-8 encoding. bytes used directly. All other types
    via str().
    """
    if isinstance(value, (dict, list)):
        data = jcs_canonicalize(value)
    elif isinstance(value, str):
        data = value.encode("utf-8")
    elif isinstance(value, bytes):
        data = value
    else:
        data = str(value).encode("utf-8")
    return hashlib.sha256(data).hexdigest()
